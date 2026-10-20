/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include <string.h>
#include <unistd.h>

#include <glib.h>
#include <gnutls/crypto.h>

#include <p11-kit/pkcs11.h>

#include "mechanism.h"
#include "objects.h"
#include "portal.h"
#include "constants.h"

#define PORTAL_SLOT_ID 1UL

/* Non-hashing mechanisms accept only bounded digest input. */
#define PRE_HASHED_LIMIT 512

/* TLS 1.0 and 1.1 MD5 || SHA1 has no portal hash name; see docs/decisions/0011-client-side-pkcs11-module.md. */
#define TLS10_MD5_SHA1_LENGTH 36

typedef struct
{
	CK_SESSION_HANDLE handle;
	/* Session serials never restart, even when C_Initialize reuses handles. */
	guint serial;
	CK_FLAGS flags;

	gboolean find_active;
	GArray* find_results;
	guint find_position;

	gboolean sign_active;
	const PortalMechanism* sign_mechanism;
	const char* sign_hash;
	const char* sign_mgf;
	gboolean sign_have_salt;
	guint32 sign_salt;
	gnutls_hash_hd_t sign_digest;
	GByteArray* sign_buffer;

	gboolean decrypt_active;
	const char* decrypt_hash;
	const char* decrypt_mgf1_hash;
	GBytes* decrypt_label;
} PortalSession;

static GMutex module_lock;
static GCond module_acquire_cond;
static gboolean module_acquiring;
static gboolean module_initialized;
/* The lifecycle generation distinguishes module initializations across unlocked waits. */
static guint module_lifecycle;
/* Finalization blocks new work before releasing the lock. */
static gboolean module_finalizing;
static guint module_session_serial;
static PortalClient* module_client;
static PortalGrant* module_grant;
static PortalObjects* module_objects;
static guint module_generation;
static GHashTable* module_sessions;
static CK_SESSION_HANDLE module_next_session;
static gboolean module_logged_in;
static guint module_slot_events;
static gboolean module_enumerate;
static GHashTable* module_issued_ids;
static gint64 module_refusal_time;
static char module_serial[PKCS11_PORTAL_TOKEN_SERIAL_SIZE + 1];

static void pad_field(CK_UTF8CHAR* field, gsize size, const char* value)
{
	gsize length = MIN(strlen(value), size);

	memset(field, ' ', size);
	memcpy(field, value, length);
}

static CK_RV portal_error_to_rv(const GError* error)
{
	if (error == NULL)
		return CKR_FUNCTION_FAILED;

	if (error->domain != PKCS11_PORTAL_ERROR)
		return CKR_FUNCTION_FAILED;

	switch (error->code)
	{
		case PKCS11_PORTAL_ERROR_CANCELLED:
			return CKR_FUNCTION_CANCELED;
		case PKCS11_PORTAL_ERROR_INVALIDATED:
			return CKR_DEVICE_REMOVED;
		case PKCS11_PORTAL_ERROR_UNAVAILABLE:
			return CKR_TOKEN_NOT_PRESENT;
		case PKCS11_PORTAL_ERROR_PIN_LOCKED:
			return CKR_PIN_LOCKED;
		case PKCS11_PORTAL_ERROR_DEVICE:
			return CKR_DEVICE_ERROR;
		case PKCS11_PORTAL_ERROR_LOGIN_REQUIRED:
			return CKR_USER_NOT_LOGGED_IN;
		case PKCS11_PORTAL_ERROR_INVALID_REQUEST:
			return CKR_ARGUMENTS_BAD;
		default:
			return CKR_FUNCTION_FAILED;
	}
}

static void session_reset_sign(PortalSession* session)
{
	session->sign_active = FALSE;
	session->sign_mechanism = NULL;
	session->sign_hash = NULL;
	session->sign_mgf = NULL;
	session->sign_have_salt = FALSE;
	session->sign_salt = 0;

	if (session->sign_digest != NULL)
	{
		gnutls_hash_deinit(session->sign_digest, NULL);
		session->sign_digest = NULL;
	}

	g_clear_pointer(&session->sign_buffer, g_byte_array_unref);
}

static void session_reset_decrypt(PortalSession* session)
{
	session->decrypt_active = FALSE;
	session->decrypt_hash = NULL;
	session->decrypt_mgf1_hash = NULL;
	g_clear_pointer(&session->decrypt_label, g_bytes_unref);
}

static void session_free(gpointer data)
{
	PortalSession* session = data;

	session_reset_sign(session);
	session_reset_decrypt(session);
	g_clear_pointer(&session->find_results, g_array_unref);
	g_free(session);
}

static gboolean grant_still_good(void);

static PortalSession* session_lookup(CK_SESSION_HANDLE handle)
{
	if (module_sessions == NULL)
		return NULL;

	/* Every supported session operation observes grant invalidation before using state. */
	grant_still_good();
	return g_hash_table_lookup(module_sessions, GUINT_TO_POINTER(handle));
}

/** Revalidate lifecycle and session serial after every unlocked wait because handles can be reused. */
static PortalSession* session_revalidate(CK_SESSION_HANDLE handle, guint lifecycle,
                                         guint serial)
{
	PortalSession* session;

	if (module_finalizing || !module_initialized || module_lifecycle != lifecycle)
		return NULL;

	session = session_lookup(handle);
	if (session == NULL || session->serial != serial)
		return NULL;

	return session;
}

static void drop_objects(void)
{
	GHashTableIter iter;
	gpointer value;

	/* Pending operations must never use a replacement grant. */
	g_hash_table_iter_init(&iter, module_sessions);
	while (g_hash_table_iter_next(&iter, NULL, &value))
	{
		session_reset_sign(value);
		session_reset_decrypt(value);
	}

	g_clear_pointer(&module_objects, portal_objects_free);
	g_clear_pointer(&module_grant, portal_grant_free);
}

static void release_grant(void)
{
	module_generation++;

	if (module_grant != NULL && !portal_client_grant_gone(module_client, module_grant))
		portal_client_release(module_client, module_grant);

	drop_objects();
}

static gboolean grant_still_good(void)
{
	if (module_grant == NULL)
		return FALSE;

	if (!portal_client_grant_gone(module_client, module_grant) &&
	    (module_grant->expires_at == 0 ||
	     g_get_real_time() / G_USEC_PER_SEC < module_grant->expires_at))
		return TRUE;

	/* NSS detects reinsertion through the defunct session, even between presence polls. */
	g_debug("Grant ended; invalidating sessions");
	release_grant();
	g_hash_table_remove_all(module_sessions);
	module_logged_in = FALSE;
	module_slot_events++;
	return FALSE;
}

static CK_RV operation_session_lookup(CK_SESSION_HANDLE handle, PortalSession** session)
{
	if (module_grant != NULL && g_hash_table_contains(module_sessions, GUINT_TO_POINTER(handle)) &&
	    portal_client_grant_gone(module_client, module_grant))
	{
		grant_still_good();
		return CKR_DEVICE_REMOVED;
	}

	*session = session_lookup(handle);
	return *session != NULL ? CKR_OK : CKR_SESSION_HANDLE_INVALID;
}

/** Called with module_lock held; releases it during acquisition, so all prior state requires revalidation. */
static gboolean ensure_grant(CK_ATTRIBUTE_PTR templ, CK_ULONG count, CK_SESSION_HANDLE handle,
                             guint lifecycle, guint serial)
{
	g_autoptr(GError) error = NULL;
	PortalClient* client;
	PortalGrant* grant;
	guint generation;

	/* Concurrent searches share one acquisition and grant. */
	while (module_acquiring && !module_finalizing)
		g_cond_wait(&module_acquire_cond, &module_lock);

	if (module_acquiring || session_revalidate(handle, lifecycle, serial) == NULL)
		return FALSE;

	if (grant_still_good())
		return TRUE;

	if (session_revalidate(handle, lifecycle, serial) == NULL ||
	    !portal_client_available(module_client))
		return FALSE;

	if (!portal_template_wants_credential(templ, count, module_issued_ids, module_enumerate))
		return FALSE;

	if (module_refusal_time != 0)
	{
		gint64 age = g_get_monotonic_time() - module_refusal_time;

		if (age < PKCS11_PORTAL_REFUSAL_GRACE_SECONDS * G_USEC_PER_SEC)
			return FALSE;
		else
			module_refusal_time = 0;
	}

	/* C_Finalize waits for module_acquiring before freeing the client. */
	client = module_client;
	generation = module_generation;
	module_acquiring = TRUE;
	g_mutex_unlock(&module_lock);

	grant = portal_client_acquire(client, &error);

	g_mutex_lock(&module_lock);
	module_acquiring = FALSE;
	g_cond_broadcast(&module_acquire_cond);

	if (grant == NULL)
	{
		if (g_error_matches(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_CANCELLED))
		{
			module_refusal_time = g_get_monotonic_time();
		}

		g_debug("no credential: %s", error != NULL ? error->message : "unavailable");
		return FALSE;
	}

	/* Grant release invalidates acquisitions that were already in progress. */
	if (module_client != client || module_generation != generation ||
	    session_revalidate(handle, lifecycle, serial) == NULL)
	{
		portal_client_release(client, grant);
		portal_grant_free(grant);
		return FALSE;
	}

	if (module_grant != NULL)
	{
		portal_client_release(client, grant);
		portal_grant_free(grant);
		return grant_still_good();
	}

	module_grant = grant;

	module_objects = portal_objects_new(module_grant, ++module_generation, &error);
	if (module_objects == NULL)
	{
		g_debug("Granted certificate object creation failed");
		release_grant();
		return FALSE;
	}

	g_hash_table_add(module_issued_ids, g_bytes_ref(module_objects->identifier));

	return TRUE;
}

static CK_FUNCTION_LIST function_list;
static CK_FUNCTION_LIST_3_0 function_list_3_0;

#define MODULE_CHECK()                                                                        \
	do                                                                                        \
	{                                                                                         \
		if (!g_atomic_int_get(&module_initialized))                                           \
			return CKR_CRYPTOKI_NOT_INITIALIZED;                                              \
	} while (0)

CK_RV C_Initialize(void* init_args)
{
	CK_C_INITIALIZE_ARGS* args = init_args;

	g_mutex_lock(&module_lock);

	if (module_initialized)
	{
		g_mutex_unlock(&module_lock);
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	}

	if (args != NULL)
	{
		gboolean any_mutex = args->CreateMutex != NULL || args->DestroyMutex != NULL ||
		                     args->LockMutex != NULL || args->UnlockMutex != NULL;
		gboolean all_mutex = args->CreateMutex != NULL && args->DestroyMutex != NULL &&
		                     args->LockMutex != NULL && args->UnlockMutex != NULL;

		if (args->pReserved != NULL &&
		    strcmp(args->pReserved, "enumerate=1") != 0 &&
		    strcmp(args->pReserved, "enumerate=0") != 0)
		{
			g_mutex_unlock(&module_lock);
			return CKR_ARGUMENTS_BAD;
		}

		if (any_mutex && !all_mutex)
		{
			g_mutex_unlock(&module_lock);
			return CKR_ARGUMENTS_BAD;
		}

		if (all_mutex && (args->flags & CKF_OS_LOCKING_OK) == 0)
		{
			g_mutex_unlock(&module_lock);
			return CKR_CANT_LOCK;
		}
	}

	g_snprintf(module_serial, sizeof(module_serial), "%s%013X",
	           PKCS11_PORTAL_TOKEN_SERIAL_PREFIX, (unsigned) (getpid() & 0x1fffffff));

	module_enumerate = args != NULL && g_strcmp0(args->pReserved, "enumerate=1") == 0;
	module_issued_ids = g_hash_table_new_full(g_bytes_hash, g_bytes_equal,
	                                        (GDestroyNotify) g_bytes_unref, NULL);
	module_sessions = g_hash_table_new_full(NULL, NULL, NULL, session_free);
	module_next_session = 1;
	module_lifecycle++;
	module_finalizing = FALSE;
	module_logged_in = FALSE;
	module_refusal_time = 0;
	module_slot_events = 0;

	if (portal_client_self_excluded())
	{
		g_debug("Portal module disabled in this process; no slot is available");
	}
	else
	{
		module_client = portal_client_new();
	}

	g_atomic_int_set(&module_initialized, TRUE);
	g_mutex_unlock(&module_lock);

	return CKR_OK;
}

CK_RV C_Finalize(void* reserved)
{
	if (reserved != NULL)
		return CKR_ARGUMENTS_BAD;

	g_mutex_lock(&module_lock);

	if (!module_initialized)
	{
		g_mutex_unlock(&module_lock);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	module_finalizing = TRUE;
	g_cond_broadcast(&module_acquire_cond);

	if (module_acquiring)
	{
		portal_client_cancel(module_client);

		while (module_acquiring)
			g_cond_wait(&module_acquire_cond, &module_lock);
	}

	release_grant();

	g_clear_pointer(&module_sessions, g_hash_table_unref);
	g_clear_pointer(&module_issued_ids, g_hash_table_unref);
	g_clear_pointer(&module_client, portal_client_free);

	module_logged_in = FALSE;
	module_finalizing = FALSE;
	g_atomic_int_set(&module_initialized, FALSE);
	g_cond_broadcast(&module_acquire_cond);
	g_mutex_unlock(&module_lock);

	return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO* info)
{
	MODULE_CHECK();

	if (info == NULL)
		return CKR_ARGUMENTS_BAD;

	memset(info, 0, sizeof(*info));
	info->cryptokiVersion.major = 2;
	info->cryptokiVersion.minor = 40;
	pad_field(info->manufacturerID, sizeof(info->manufacturerID),
	          XDG_PORTAL_CERTIFICATE_TOKEN_MANUFACTURER);
	pad_field(info->libraryDescription, sizeof(info->libraryDescription),
	          PKCS11_PORTAL_LIBRARY_DESCRIPTION);
	info->libraryVersion.major = 0;
	info->libraryVersion.minor = 1;

	return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST** list)
{
	if (list == NULL)
		return CKR_ARGUMENTS_BAD;

	*list = &function_list;
	return CKR_OK;
}

CK_RV C_GetInterfaceList(CK_INTERFACE* interfaces, unsigned long* count)
{
	static const CK_INTERFACE interface_list[] = {
		{ (char*) "PKCS 11", &function_list_3_0, 0 },
		{ (char*) "PKCS 11", &function_list, 0 },
	};

	if (count == NULL)
		return CKR_ARGUMENTS_BAD;

	if (interfaces == NULL)
	{
		*count = G_N_ELEMENTS(interface_list);
		return CKR_OK;
	}

	if (*count < G_N_ELEMENTS(interface_list))
	{
		*count = G_N_ELEMENTS(interface_list);
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy(interfaces, interface_list, sizeof(interface_list));
	*count = G_N_ELEMENTS(interface_list);

	return CKR_OK;
}

CK_RV C_GetInterface(unsigned char* interface_name, CK_VERSION* version,
                     CK_INTERFACE** interface, CK_FLAGS flags)
{
	static CK_INTERFACE interface_3_0 = { (char*) "PKCS 11", &function_list_3_0, 0 };
	static CK_INTERFACE interface_2_40 = { (char*) "PKCS 11", &function_list, 0 };

	if (interface == NULL)
		return CKR_ARGUMENTS_BAD;

	if (interface_name != NULL && strcmp((const char*) interface_name, "PKCS 11") != 0)
		return CKR_ARGUMENTS_BAD;

	/* No fork-safety flags are advertised. */
	if (flags != 0)
		return CKR_ARGUMENTS_BAD;

	if (version == NULL || (version->major == 3 && version->minor == 0))
		*interface = &interface_3_0;
	else if (version->major == 2 && version->minor == 40)
		*interface = &interface_2_40;
	else
		return CKR_ARGUMENTS_BAD;

	return CKR_OK;
}

CK_RV C_GetSlotList(unsigned char token_present, CK_SLOT_ID* slot_list, unsigned long* count)
{
	CK_SLOT_ID slot = PORTAL_SLOT_ID;
	gboolean present;

	MODULE_CHECK();

	if (count == NULL)
		return CKR_ARGUMENTS_BAD;

	g_mutex_lock(&module_lock);
	present = portal_client_available(module_client);
	g_mutex_unlock(&module_lock);

	/* An unavailable portal leaves the initialized module with no token. */
	if (!present)
	{
		*count = 0;
		return CKR_OK;
	}

	(void) token_present;

	if (slot_list == NULL)
	{
		*count = 1;
		return CKR_OK;
	}

	if (*count < 1)
	{
		*count = 1;
		return CKR_BUFFER_TOO_SMALL;
	}

	slot_list[0] = slot;
	*count = 1;

	return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slot_id, CK_SLOT_INFO* info)
{
	MODULE_CHECK();

	if (info == NULL)
		return CKR_ARGUMENTS_BAD;
	if (slot_id != PORTAL_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	memset(info, 0, sizeof(*info));
	pad_field(info->slotDescription, sizeof(info->slotDescription),
	          PKCS11_PORTAL_SLOT_DESCRIPTION);
	pad_field(info->manufacturerID, sizeof(info->manufacturerID),
	          XDG_PORTAL_CERTIFICATE_TOKEN_MANUFACTURER);
	g_mutex_lock(&module_lock);
	grant_still_good();
	info->flags = CKF_REMOVABLE_DEVICE;
	if (portal_client_available(module_client))
		info->flags |= CKF_TOKEN_PRESENT;
	g_mutex_unlock(&module_lock);

	return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slot_id, CK_TOKEN_INFO* info)
{
	MODULE_CHECK();

	if (info == NULL)
		return CKR_ARGUMENTS_BAD;
	if (slot_id != PORTAL_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	g_mutex_lock(&module_lock);
	if (!portal_client_available(module_client))
	{
		g_mutex_unlock(&module_lock);
		return CKR_TOKEN_NOT_PRESENT;
	}
	g_mutex_unlock(&module_lock);

	memset(info, 0, sizeof(*info));
	pad_field(info->label, sizeof(info->label), XDG_PORTAL_CERTIFICATE_TOKEN_LABEL);
	pad_field(info->manufacturerID, sizeof(info->manufacturerID),
	          XDG_PORTAL_CERTIFICATE_TOKEN_MANUFACTURER);
	pad_field(info->model, sizeof(info->model), XDG_PORTAL_CERTIFICATE_TOKEN_MODEL);
	pad_field(info->serialNumber, sizeof(info->serialNumber), module_serial);

	/* Backend lazy login requires CKF_PROTECTED_AUTHENTICATION_PATH without CKF_LOGIN_REQUIRED; see docs/SOURCES.md and docs/TESTING.md. */
	info->flags = CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH |
	              CKF_USER_PIN_INITIALIZED;

	info->ulMaxSessionCount = CK_UNAVAILABLE_INFORMATION;
	info->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
	info->ulMaxRwSessionCount = 0;
	info->ulRwSessionCount = 0;
	info->ulMaxPinLen = 0;
	info->ulMinPinLen = 0;
	info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	memset(info->utcTime, ' ', sizeof(info->utcTime));

	return CKR_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slot_id, CK_MECHANISM_TYPE* mechanism_list,
                         unsigned long* count)
{
	g_auto(GStrv) mechanisms = NULL;
	g_autoptr(GArray) list = NULL;
	unsigned long available;

	MODULE_CHECK();

	if (count == NULL)
		return CKR_ARGUMENTS_BAD;
	if (slot_id != PORTAL_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	g_mutex_lock(&module_lock);

	mechanisms = portal_client_dup_mechanisms(module_client);
	if (mechanisms == NULL)
	{
		g_mutex_unlock(&module_lock);
		return CKR_TOKEN_NOT_PRESENT;
	}

	list = portal_mechanism_list((const char* const*) mechanisms);
	available = list->len;

	if (mechanism_list == NULL)
	{
		*count = available;
		g_mutex_unlock(&module_lock);
		return CKR_OK;
	}

	if (*count < available)
	{
		*count = available;
		g_mutex_unlock(&module_lock);
		return CKR_BUFFER_TOO_SMALL;
	}

	for (unsigned long i = 0; i < available; i++)
		mechanism_list[i] = g_array_index(list, CK_MECHANISM_TYPE, i);
	*count = available;

	g_mutex_unlock(&module_lock);
	return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slot_id, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO* info)
{
	const PortalMechanism* mechanism;
	g_auto(GStrv) mechanisms = NULL;
	CK_RV rv = CKR_OK;

	MODULE_CHECK();

	if (info == NULL)
		return CKR_ARGUMENTS_BAD;
	if (slot_id != PORTAL_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	mechanism = portal_mechanism_lookup(type);

	g_mutex_lock(&module_lock);

	mechanisms = portal_client_dup_mechanisms(module_client);
	if (mechanisms == NULL)
		rv = CKR_TOKEN_NOT_PRESENT;
	else if (mechanism == NULL ||
	         !portal_mechanism_available(mechanism, (const char* const*) mechanisms))
		rv = CKR_MECHANISM_INVALID;

	g_mutex_unlock(&module_lock);

	if (rv != CKR_OK)
		return rv;

	memset(info, 0, sizeof(*info));

	if (strcmp(mechanism->portal_mechanism, "ECDSA") == 0)
	{
		info->ulMinKeySize = 256;
		info->ulMaxKeySize = 521;
	}
	else
	{
		info->ulMinKeySize = 1024;
		info->ulMaxKeySize = 8192;
	}

	info->flags = mechanism->can_sign ? CKF_SIGN : CKF_DECRYPT;

	return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slot_id, CK_FLAGS flags, void* application, CK_NOTIFY notify,
                    CK_SESSION_HANDLE* session_handle)
{
	PortalSession* session;

	MODULE_CHECK();

	if (session_handle == NULL)
		return CKR_ARGUMENTS_BAD;
	if (slot_id != PORTAL_SLOT_ID)
		return CKR_SLOT_ID_INVALID;
	if ((flags & CKF_SERIAL_SESSION) == 0)
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
	if ((flags & CKF_RW_SESSION) != 0)
		return CKR_TOKEN_WRITE_PROTECTED;

	g_mutex_lock(&module_lock);

	if (module_finalizing)
	{
		g_mutex_unlock(&module_lock);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!portal_client_available(module_client))
	{
		g_mutex_unlock(&module_lock);
		return CKR_TOKEN_NOT_PRESENT;
	}

	/* Retire old sessions before a new session can acquire a replacement grant. */
	grant_still_good();
	session = g_new0(PortalSession, 1);
	session->handle = module_next_session++;
	session->serial = ++module_session_serial;
	session->flags = flags;
	g_hash_table_insert(module_sessions, GUINT_TO_POINTER(session->handle), session);
	*session_handle = session->handle;

	g_mutex_unlock(&module_lock);

	return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE session_handle)
{
	CK_RV rv = CKR_OK;

	MODULE_CHECK();

	g_mutex_lock(&module_lock);

	if (!g_hash_table_remove(module_sessions, GUINT_TO_POINTER(session_handle)))
		rv = CKR_SESSION_HANDLE_INVALID;

	/* Ordinary PKCS#11 session closure preserves the grant for subsequent imports and signatures. */
	if (rv == CKR_OK && g_hash_table_size(module_sessions) == 0)
		module_logged_in = FALSE;

	g_mutex_unlock(&module_lock);

	return rv;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slot_id)
{
	MODULE_CHECK();

	if (slot_id != PORTAL_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	g_mutex_lock(&module_lock);
	g_hash_table_remove_all(module_sessions);
	release_grant();
	module_logged_in = FALSE;
	g_mutex_unlock(&module_lock);

	return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE session_handle, CK_SESSION_INFO* info)
{
	PortalSession* session;

	MODULE_CHECK();

	if (info == NULL)
		return CKR_ARGUMENTS_BAD;

	g_mutex_lock(&module_lock);

	session = session_lookup(session_handle);
	if (session == NULL)
	{
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
	}

	memset(info, 0, sizeof(*info));
	info->slotID = PORTAL_SLOT_ID;
	info->state = module_logged_in ? CKS_RO_USER_FUNCTIONS : CKS_RO_PUBLIC_SESSION;
	info->flags = session->flags;
	info->ulDeviceError = 0;

	g_mutex_unlock(&module_lock);

	return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE session_handle, CK_USER_TYPE user_type, unsigned char* pin,
              unsigned long pin_len)
{
	CK_RV rv = CKR_OK;

	MODULE_CHECK();

	/* PIN arguments must never be read, copied or forwarded; the backend collects PINs. */
	(void) pin;
	(void) pin_len;

	if (user_type != CKU_USER)
		return CKR_USER_TYPE_INVALID;

	g_mutex_lock(&module_lock);

	if (session_lookup(session_handle) == NULL)
		rv = CKR_SESSION_HANDLE_INVALID;
	else if (module_logged_in)
		rv = CKR_USER_ALREADY_LOGGED_IN;
	else
		module_logged_in = TRUE;

	g_mutex_unlock(&module_lock);

	return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE session_handle)
{
	CK_RV rv = CKR_OK;

	MODULE_CHECK();

	g_mutex_lock(&module_lock);

	if (session_lookup(session_handle) == NULL)
		rv = CKR_SESSION_HANDLE_INVALID;
	else
	{
		if (!module_logged_in)
			rv = CKR_USER_NOT_LOGGED_IN;
		module_logged_in = FALSE;
		release_grant();
	}

	g_mutex_unlock(&module_lock);

	return rv;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE session_handle, CK_ATTRIBUTE* templ,
                        unsigned long count)
{
	PortalSession* session;
	gboolean acquired;
	guint lifecycle;
	guint serial;

	MODULE_CHECK();

	if (templ == NULL && count > 0)
		return CKR_ARGUMENTS_BAD;

	g_mutex_lock(&module_lock);

	if (module_finalizing)
	{
		g_mutex_unlock(&module_lock);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	session = session_lookup(session_handle);
	if (session == NULL)
	{
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
	}

	if (session->find_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_ACTIVE;
	}

	lifecycle = module_lifecycle;
	serial = session->serial;

	/* Acquisition releases module_lock; recheck session identity after it returns. */
	acquired = ensure_grant(templ, count, session_handle, lifecycle, serial);

	session = session_revalidate(session_handle, lifecycle, serial);
	if (session == NULL)
	{
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
	}

	if (session->find_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_ACTIVE;
	}

	if (acquired)
		session->find_results = portal_objects_find(module_objects, templ, count);
	else
		session->find_results = g_array_new(FALSE, FALSE, sizeof(CK_OBJECT_HANDLE));

	session->find_position = 0;
	session->find_active = TRUE;

	g_debug("search returned %u objects", session->find_results->len);

	g_mutex_unlock(&module_lock);

	return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE* objects,
                    unsigned long max_count, unsigned long* count)
{
	PortalSession* session;
	unsigned long produced = 0;

	MODULE_CHECK();

	if (count == NULL || (objects == NULL && max_count > 0))
		return CKR_ARGUMENTS_BAD;

	g_mutex_lock(&module_lock);

	session = session_lookup(session_handle);
	if (session == NULL)
	{
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
	}

	if (!session->find_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	while (produced < max_count && session->find_position < session->find_results->len)
	{
		objects[produced++] =
		    g_array_index(session->find_results, CK_OBJECT_HANDLE, session->find_position++);
	}

	*count = produced;

	g_mutex_unlock(&module_lock);

	return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE session_handle)
{
	PortalSession* session;

	MODULE_CHECK();

	g_mutex_lock(&module_lock);

	session = session_lookup(session_handle);
	if (session == NULL)
	{
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
	}

	if (!session->find_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	session->find_active = FALSE;
	session->find_position = 0;
	g_clear_pointer(&session->find_results, g_array_unref);

	g_mutex_unlock(&module_lock);

	return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE object_handle,
                          CK_ATTRIBUTE* templ, unsigned long count)
{
	PortalSession* session;
	PortalObject* object;
	CK_RV rv;

	MODULE_CHECK();

	if (templ == NULL && count > 0)
		return CKR_ARGUMENTS_BAD;

	g_mutex_lock(&module_lock);

	session = session_lookup(session_handle);
	if (session == NULL)
	{
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
	}

	object = portal_objects_lookup(module_objects, object_handle);
	if (object == NULL)
	{
		g_debug("C_GetAttributeValue: invalid object handle");
		g_mutex_unlock(&module_lock);
		return CKR_OBJECT_HANDLE_INVALID;
	}

	rv = portal_object_get_attributes(object, templ, count);

	g_mutex_unlock(&module_lock);

	return rv;
}

static gsize signature_length(void)
{
	if (module_grant == NULL || module_grant->key_size == 0)
		return 0;

	if (g_strcmp0(module_grant->key_type, "EC") == 0)
		return 2 * ((module_grant->key_size + 7) / 8);

	return (module_grant->key_size + 7) / 8;
}

static CK_RV sign_setup(PortalSession* session, CK_MECHANISM* mechanism)
{
	const PortalMechanism* entry = portal_mechanism_lookup(mechanism->mechanism);
	gboolean key_is_ec = g_strcmp0(module_grant->key_type, "EC") == 0;
	gboolean mechanism_is_ec;

	if (entry == NULL || !entry->can_sign)
		return CKR_MECHANISM_INVALID;
	if (!portal_mechanism_available(
	        entry, (const char* const*) module_grant->supported_mechanisms))
		return CKR_MECHANISM_INVALID;

	mechanism_is_ec = strcmp(entry->portal_mechanism, "ECDSA") == 0;
	if (mechanism_is_ec != key_is_ec)
		return CKR_KEY_TYPE_INCONSISTENT;

	session->sign_hash = entry->hash;
	session->sign_mgf = NULL;
	session->sign_have_salt = FALSE;

	if (entry->pss)
	{
		CK_RSA_PKCS_PSS_PARAMS* parameters = mechanism->pParameter;
		const char* hash;
		const char* mgf_hash;

		if (parameters == NULL || mechanism->ulParameterLen != sizeof(*parameters))
			return CKR_MECHANISM_PARAM_INVALID;

		hash = portal_hash_from_ck_digest(parameters->hashAlg);
		if (hash == NULL)
			return CKR_MECHANISM_PARAM_INVALID;
		if (entry->hash != NULL && strcmp(entry->hash, hash) != 0)
			return CKR_MECHANISM_PARAM_INVALID;

		/* Portal requests from this module use matching signature and MGF1 hashes. */
		mgf_hash = portal_mgf_hash(parameters->mgf);
		if (mgf_hash == NULL || strcmp(mgf_hash, hash) != 0)
			return CKR_MECHANISM_PARAM_INVALID;

		/* The wire salt length is uint32; reject values lost by narrowing. */
		if (parameters->sLen != (CK_ULONG) (guint32) parameters->sLen)
			return CKR_MECHANISM_PARAM_INVALID;

		session->sign_hash = hash;
		session->sign_mgf = portal_mgf_name(parameters->mgf);
		session->sign_have_salt = TRUE;
		session->sign_salt = (guint32) parameters->sLen;
	}
	else if (mechanism->pParameter != NULL || mechanism->ulParameterLen != 0)
	{
		return CKR_MECHANISM_PARAM_INVALID;
	}

	if (entry->hash_locally)
	{
		int digest = portal_hash_gnutls(entry->hash);

		if (gnutls_hash_init(&session->sign_digest, digest) < 0)
			return CKR_FUNCTION_FAILED;
	}
	else
	{
		session->sign_buffer = g_byte_array_new();
	}

	session->sign_mechanism = entry;
	session->sign_active = TRUE;

	return CKR_OK;
}

static CK_RV sign_feed(PortalSession* session, const unsigned char* data, unsigned long size)
{
	if (size == 0)
		return CKR_OK;
	if (data == NULL)
		return CKR_ARGUMENTS_BAD;

	if (session->sign_digest != NULL)
	{
		if (gnutls_hash(session->sign_digest, data, size) < 0)
			return CKR_FUNCTION_FAILED;
		return CKR_OK;
	}

	/* Subtract to avoid unsigned overflow in len + size. */
	if (session->sign_buffer->len > PRE_HASHED_LIMIT ||
	    size > PRE_HASHED_LIMIT - session->sign_buffer->len)
		return CKR_DATA_LEN_RANGE;

	g_byte_array_append(session->sign_buffer, data, (guint) size);

	return CKR_OK;
}

static CK_RV sign_perform(PortalSession* session, GBytes** signature)
{
	const PortalMechanism* entry = session->sign_mechanism;
	g_autoptr(GError) error = NULL;
	guint8 digest[64];
	const guint8* data = NULL;
	gsize size = 0;
	const char* hash = session->sign_hash;

	if (entry->hash_locally)
	{
		gnutls_hash_deinit(session->sign_digest, digest);
		session->sign_digest = NULL;
		data = digest;
		size = portal_hash_length(entry->hash);
	}
	else if (entry->digest_info)
	{
		if (!portal_digestinfo_parse(session->sign_buffer->data, session->sign_buffer->len,
		                             &hash, &data, &size))
		{
			/* The portal cannot represent the TLS 1.0 and 1.1 MD5 || SHA1 digest. */
			return session->sign_buffer->len == TLS10_MD5_SHA1_LENGTH
			           ? CKR_MECHANISM_INVALID
			           : CKR_DATA_INVALID;
		}
	}
	else if (entry->infer_hash)
	{
		hash = portal_hash_for_length(session->sign_buffer->len);
		if (hash == NULL)
			return CKR_DATA_LEN_RANGE;
		data = session->sign_buffer->data;
		size = session->sign_buffer->len;
	}
	else
	{
		if (session->sign_buffer->len != portal_hash_length(hash))
			return CKR_DATA_LEN_RANGE;
		data = session->sign_buffer->data;
		size = session->sign_buffer->len;
	}

	if (!portal_client_sign(module_client, module_grant, entry->portal_mechanism, hash,
	                        session->sign_mgf, session->sign_have_salt, session->sign_salt,
	                        data, size, signature, &error))
	{
		g_debug("Sign failed");
		return portal_error_to_rv(error);
	}

	return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM* mechanism,
                 CK_OBJECT_HANDLE key)
{
	PortalSession* session;
	PortalObject* object;
	CK_RV rv;

	MODULE_CHECK();

	if (mechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	g_mutex_lock(&module_lock);

	session = session_lookup(session_handle);
	if (session == NULL)
	{
		g_debug("C_SignInit: invalid session handle");
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
	}

	if (session->sign_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_ACTIVE;
	}

	if (module_grant == NULL)
	{
		g_debug("%s: no granted key", G_STRFUNC);
		g_mutex_unlock(&module_lock);
		return CKR_KEY_HANDLE_INVALID;
	}

	object = portal_objects_lookup(module_objects, key);
	if (object == NULL || object->object_class != CKO_PRIVATE_KEY)
	{
		g_debug("%s: invalid key handle", G_STRFUNC);
		g_mutex_unlock(&module_lock);
		return CKR_KEY_HANDLE_INVALID;
	}

	if (!module_grant->may_sign)
	{
		g_mutex_unlock(&module_lock);
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	rv = sign_setup(session, mechanism);
	if (rv != CKR_OK)
		session_reset_sign(session);

	g_mutex_unlock(&module_lock);

	return rv;
}

static CK_RV sign_finish(PortalSession* session, unsigned char* out, unsigned long* out_len)
{
	g_autoptr(GBytes) signature = NULL;
	gsize expected = signature_length();
	gsize size = 0;
	const guint8* data = NULL;
	CK_RV rv;

	if (out == NULL)
	{
		*out_len = expected;
		return CKR_OK;
	}

	if (*out_len < expected)
	{
		*out_len = expected;
		return CKR_BUFFER_TOO_SMALL;
	}

	rv = sign_perform(session, &signature);
	if (rv != CKR_OK)
	{
		session_reset_sign(session);
		return rv;
	}

	data = g_bytes_get_data(signature, &size);

	if (size > *out_len)
	{
		session_reset_sign(session);
		return CKR_FUNCTION_FAILED;
	}

	memcpy(out, data, size);
	*out_len = size;
	session_reset_sign(session);

	return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE session_handle, unsigned char* data, unsigned long data_len,
             unsigned char* signature, unsigned long* signature_len)
{
	PortalSession* session;
	CK_RV rv;

	MODULE_CHECK();

	if (signature_len == NULL)
		return CKR_ARGUMENTS_BAD;

	g_mutex_lock(&module_lock);

	rv = operation_session_lookup(session_handle, &session);
	if (rv != CKR_OK)
	{
		g_mutex_unlock(&module_lock);
		return rv;
	}

	if (!session->sign_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	/* Size queries preserve the input and operation state. */
	if (signature == NULL)
	{
		*signature_len = signature_length();
		g_mutex_unlock(&module_lock);
		return CKR_OK;
	}

	if (*signature_len < signature_length())
	{
		*signature_len = signature_length();
		g_mutex_unlock(&module_lock);
		return CKR_BUFFER_TOO_SMALL;
	}

	rv = sign_feed(session, data, data_len);
	if (rv != CKR_OK)
	{
		session_reset_sign(session);
		g_mutex_unlock(&module_lock);
		return rv;
	}

	rv = sign_finish(session, signature, signature_len);

	g_mutex_unlock(&module_lock);

	return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE session_handle, unsigned char* part, unsigned long part_len)
{
	PortalSession* session;
	CK_RV rv;

	MODULE_CHECK();

	g_mutex_lock(&module_lock);

	rv = operation_session_lookup(session_handle, &session);
	if (rv != CKR_OK)
	{
		g_mutex_unlock(&module_lock);
		return rv;
	}

	if (!session->sign_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	rv = sign_feed(session, part, part_len);
	if (rv != CKR_OK)
		session_reset_sign(session);

	g_mutex_unlock(&module_lock);

	return rv;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE session_handle, unsigned char* signature,
                  unsigned long* signature_len)
{
	PortalSession* session;
	CK_RV rv;

	MODULE_CHECK();

	if (signature_len == NULL)
		return CKR_ARGUMENTS_BAD;

	g_mutex_lock(&module_lock);

	rv = operation_session_lookup(session_handle, &session);
	if (rv != CKR_OK)
	{
		g_mutex_unlock(&module_lock);
		return rv;
	}

	if (!session->sign_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	rv = sign_finish(session, signature, signature_len);

	g_mutex_unlock(&module_lock);

	return rv;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM* mechanism,
                    CK_OBJECT_HANDLE key)
{
	PortalSession* session;
	PortalObject* object;
	CK_RSA_PKCS_OAEP_PARAMS* parameters;
	const char* hash;
	const char* mgf_hash;

	MODULE_CHECK();

	if (mechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	/* PKCS#1 v1.5 decryption exposes a padding oracle; only RSA_OAEP is supported. */
	if (mechanism->mechanism != CKM_RSA_PKCS_OAEP)
		return CKR_MECHANISM_INVALID;

	g_mutex_lock(&module_lock);

	session = session_lookup(session_handle);
	if (session == NULL)
	{
		g_debug("C_DecryptInit: invalid session handle");
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
	}

	if (session->decrypt_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_ACTIVE;
	}

	if (module_grant == NULL)
	{
		g_debug("%s: no granted key", G_STRFUNC);
		g_mutex_unlock(&module_lock);
		return CKR_KEY_HANDLE_INVALID;
	}

	object = portal_objects_lookup(module_objects, key);
	if (object == NULL || object->object_class != CKO_PRIVATE_KEY)
	{
		g_debug("%s: invalid key handle", G_STRFUNC);
		g_mutex_unlock(&module_lock);
		return CKR_KEY_HANDLE_INVALID;
	}

	if (!module_grant->may_decrypt)
	{
		g_mutex_unlock(&module_lock);
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	if (!portal_mechanism_available(portal_mechanism_lookup(CKM_RSA_PKCS_OAEP),
	                                (const char* const*) module_grant->supported_mechanisms))
	{
		g_mutex_unlock(&module_lock);
		return CKR_MECHANISM_INVALID;
	}

	parameters = mechanism->pParameter;
	if (parameters == NULL || mechanism->ulParameterLen != sizeof(*parameters))
	{
		g_mutex_unlock(&module_lock);
		return CKR_MECHANISM_PARAM_INVALID;
	}

	hash = portal_hash_from_ck_digest(parameters->hashAlg);
	mgf_hash = portal_mgf_hash(parameters->mgf);
	if (hash == NULL || mgf_hash == NULL || strcmp(hash, mgf_hash) != 0)
	{
		g_mutex_unlock(&module_lock);
		return CKR_MECHANISM_PARAM_INVALID;
	}

	if (parameters->ulSourceDataLen > 0)
	{
		if (parameters->source != CKZ_DATA_SPECIFIED || parameters->pSourceData == NULL ||
		    parameters->ulSourceDataLen > PKCS11_PORTAL_REASON_MAX)
		{
			g_mutex_unlock(&module_lock);
			return CKR_MECHANISM_PARAM_INVALID;
		}

		session->decrypt_label =
		    g_bytes_new(parameters->pSourceData, parameters->ulSourceDataLen);
	}

	session->decrypt_hash = hash;
	session->decrypt_mgf1_hash = mgf_hash;
	session->decrypt_active = TRUE;

	g_mutex_unlock(&module_lock);

	return CKR_OK;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE session_handle, unsigned char* ciphertext,
                unsigned long ciphertext_len, unsigned char* plaintext,
                unsigned long* plaintext_len)
{
	PortalSession* session;
	g_autoptr(GBytes) result = NULL;
	g_autoptr(GError) error = NULL;
	const guint8* data;
	gsize size = 0;
	CK_RV rv;

	MODULE_CHECK();

	if (plaintext_len == NULL)
		return CKR_ARGUMENTS_BAD;

	g_mutex_lock(&module_lock);

	rv = operation_session_lookup(session_handle, &session);
	if (rv != CKR_OK)
	{
		g_mutex_unlock(&module_lock);
		return rv;
	}

	if (!session->decrypt_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	/* Size queries must not prompt; the modulus size bounds the unknown plaintext length. */
	if (plaintext == NULL)
	{
		*plaintext_len = signature_length();
		g_mutex_unlock(&module_lock);
		return CKR_OK;
	}

	if (ciphertext == NULL)
	{
		session_reset_decrypt(session);
		g_mutex_unlock(&module_lock);
		return CKR_ARGUMENTS_BAD;
	}

	if (!portal_client_decrypt(module_client, module_grant, session->decrypt_hash,
	                           session->decrypt_mgf1_hash, session->decrypt_label, ciphertext,
	                           ciphertext_len, &result, &error))
	{
		rv = portal_error_to_rv(error);

		session_reset_decrypt(session);
		g_mutex_unlock(&module_lock);
		return rv;
	}

	data = g_bytes_get_data(result, &size);

	if (size > *plaintext_len)
	{
		*plaintext_len = size;
		g_mutex_unlock(&module_lock);
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy(plaintext, data, size);
	*plaintext_len = size;
	session_reset_decrypt(session);

	g_mutex_unlock(&module_lock);

	return CKR_OK;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID* slot, void* reserved)
{
	CK_RV rv = CKR_NO_EVENT;

	MODULE_CHECK();

	if (slot == NULL || reserved != NULL || (flags & ~CKF_DONT_BLOCK) != 0)
		return CKR_ARGUMENTS_BAD;
	if ((flags & CKF_DONT_BLOCK) == 0)
		return CKR_FUNCTION_NOT_SUPPORTED;

	g_mutex_lock(&module_lock);
	grant_still_good();
	if (module_slot_events > 0)
	{
		module_slot_events--;
		*slot = PORTAL_SLOT_ID;
		rv = CKR_OK;
	}
	g_mutex_unlock(&module_lock);

	return rv;
}

#define NOT_SUPPORTED(name, args)                                                             \
	CK_RV name args                                                                           \
	{                                                                                         \
		return CKR_FUNCTION_NOT_SUPPORTED;                                                    \
	}

NOT_SUPPORTED(C_InitToken, (CK_SLOT_ID s, unsigned char* p, unsigned long l, unsigned char* b))
NOT_SUPPORTED(C_InitPIN, (CK_SESSION_HANDLE s, unsigned char* p, unsigned long l))
NOT_SUPPORTED(C_SetPIN, (CK_SESSION_HANDLE s, unsigned char* o, unsigned long ol,
                         unsigned char* n, unsigned long nl))
NOT_SUPPORTED(C_GetOperationState, (CK_SESSION_HANDLE s, unsigned char* o, unsigned long* l))
NOT_SUPPORTED(C_SetOperationState, (CK_SESSION_HANDLE s, unsigned char* o, unsigned long l,
                                    CK_OBJECT_HANDLE e, CK_OBJECT_HANDLE a))
NOT_SUPPORTED(C_CreateObject, (CK_SESSION_HANDLE s, CK_ATTRIBUTE* t, unsigned long c,
                               CK_OBJECT_HANDLE* o))
NOT_SUPPORTED(C_CopyObject, (CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o, CK_ATTRIBUTE* t,
                             unsigned long c, CK_OBJECT_HANDLE* n))
NOT_SUPPORTED(C_DestroyObject, (CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o))
NOT_SUPPORTED(C_GetObjectSize, (CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o, unsigned long* z))
NOT_SUPPORTED(C_SetAttributeValue, (CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o, CK_ATTRIBUTE* t,
                                    unsigned long c))
NOT_SUPPORTED(C_EncryptInit, (CK_SESSION_HANDLE s, CK_MECHANISM* m, CK_OBJECT_HANDLE k))
NOT_SUPPORTED(C_Encrypt, (CK_SESSION_HANDLE s, unsigned char* d, unsigned long dl,
                          unsigned char* e, unsigned long* el))
NOT_SUPPORTED(C_EncryptUpdate, (CK_SESSION_HANDLE s, unsigned char* p, unsigned long pl,
                                unsigned char* e, unsigned long* el))
NOT_SUPPORTED(C_EncryptFinal, (CK_SESSION_HANDLE s, unsigned char* e, unsigned long* el))
NOT_SUPPORTED(C_DecryptUpdate, (CK_SESSION_HANDLE s, unsigned char* e, unsigned long el,
                                unsigned char* p, unsigned long* pl))
NOT_SUPPORTED(C_DecryptFinal, (CK_SESSION_HANDLE s, unsigned char* p, unsigned long* pl))
NOT_SUPPORTED(C_DigestInit, (CK_SESSION_HANDLE s, CK_MECHANISM* m))
NOT_SUPPORTED(C_Digest, (CK_SESSION_HANDLE s, unsigned char* d, unsigned long dl,
                         unsigned char* g, unsigned long* gl))
NOT_SUPPORTED(C_DigestUpdate, (CK_SESSION_HANDLE s, unsigned char* p, unsigned long pl))
NOT_SUPPORTED(C_DigestKey, (CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k))
NOT_SUPPORTED(C_DigestFinal, (CK_SESSION_HANDLE s, unsigned char* g, unsigned long* gl))
NOT_SUPPORTED(C_SignRecoverInit, (CK_SESSION_HANDLE s, CK_MECHANISM* m, CK_OBJECT_HANDLE k))
NOT_SUPPORTED(C_SignRecover, (CK_SESSION_HANDLE s, unsigned char* d, unsigned long dl,
                              unsigned char* g, unsigned long* gl))
NOT_SUPPORTED(C_VerifyInit, (CK_SESSION_HANDLE s, CK_MECHANISM* m, CK_OBJECT_HANDLE k))
NOT_SUPPORTED(C_Verify, (CK_SESSION_HANDLE s, unsigned char* d, unsigned long dl,
                         unsigned char* g, unsigned long gl))
NOT_SUPPORTED(C_VerifyUpdate, (CK_SESSION_HANDLE s, unsigned char* p, unsigned long pl))
NOT_SUPPORTED(C_VerifyFinal, (CK_SESSION_HANDLE s, unsigned char* g, unsigned long gl))
NOT_SUPPORTED(C_VerifyRecoverInit, (CK_SESSION_HANDLE s, CK_MECHANISM* m, CK_OBJECT_HANDLE k))
NOT_SUPPORTED(C_VerifyRecover, (CK_SESSION_HANDLE s, unsigned char* g, unsigned long gl,
                                unsigned char* d, unsigned long* dl))
NOT_SUPPORTED(C_DigestEncryptUpdate, (CK_SESSION_HANDLE s, unsigned char* p, unsigned long pl,
                                      unsigned char* e, unsigned long* el))
NOT_SUPPORTED(C_DecryptDigestUpdate, (CK_SESSION_HANDLE s, unsigned char* e, unsigned long el,
                                      unsigned char* p, unsigned long* pl))
NOT_SUPPORTED(C_SignEncryptUpdate, (CK_SESSION_HANDLE s, unsigned char* p, unsigned long pl,
                                    unsigned char* e, unsigned long* el))
NOT_SUPPORTED(C_DecryptVerifyUpdate, (CK_SESSION_HANDLE s, unsigned char* e, unsigned long el,
                                      unsigned char* p, unsigned long* pl))
NOT_SUPPORTED(C_GenerateKey, (CK_SESSION_HANDLE s, CK_MECHANISM* m, CK_ATTRIBUTE* t,
                              unsigned long c, CK_OBJECT_HANDLE* k))
NOT_SUPPORTED(C_GenerateKeyPair, (CK_SESSION_HANDLE s, CK_MECHANISM* m, CK_ATTRIBUTE* pt,
                                  unsigned long pc, CK_ATTRIBUTE* st, unsigned long sc,
                                  CK_OBJECT_HANDLE* pk, CK_OBJECT_HANDLE* sk))
NOT_SUPPORTED(C_WrapKey, (CK_SESSION_HANDLE s, CK_MECHANISM* m, CK_OBJECT_HANDLE w,
                          CK_OBJECT_HANDLE k, unsigned char* o, unsigned long* ol))
NOT_SUPPORTED(C_UnwrapKey, (CK_SESSION_HANDLE s, CK_MECHANISM* m, CK_OBJECT_HANDLE u,
                            unsigned char* w, unsigned long wl, CK_ATTRIBUTE* t,
                            unsigned long c, CK_OBJECT_HANDLE* k))
NOT_SUPPORTED(C_DeriveKey, (CK_SESSION_HANDLE s, CK_MECHANISM* m, CK_OBJECT_HANDLE b,
                            CK_ATTRIBUTE* t, unsigned long c, CK_OBJECT_HANDLE* k))
NOT_SUPPORTED(C_SeedRandom, (CK_SESSION_HANDLE s, unsigned char* d, unsigned long l))
NOT_SUPPORTED(C_GenerateRandom, (CK_SESSION_HANDLE s, unsigned char* d, unsigned long l))
NOT_SUPPORTED(C_GetFunctionStatus, (CK_SESSION_HANDLE s))
NOT_SUPPORTED(C_CancelFunction, (CK_SESSION_HANDLE s))

NOT_SUPPORTED(C_LoginUser, (CK_SESSION_HANDLE session, CK_USER_TYPE user_type, unsigned char* pin,
                            unsigned long pin_len, unsigned char* username,
                            unsigned long username_len))
NOT_SUPPORTED(C_SessionCancel, (CK_SESSION_HANDLE session, CK_FLAGS flags))
NOT_SUPPORTED(C_MessageEncryptInit, (CK_SESSION_HANDLE session, CK_MECHANISM* mechanism,
                                     CK_OBJECT_HANDLE key))
NOT_SUPPORTED(C_EncryptMessage, (CK_SESSION_HANDLE session, void* parameter,
                                 unsigned long parameter_len, unsigned char* associated_data,
                                 unsigned long associated_data_len, unsigned char* plaintext,
                                 unsigned long plaintext_len, unsigned char* ciphertext,
                                 unsigned long* ciphertext_len))
NOT_SUPPORTED(C_EncryptMessageBegin, (CK_SESSION_HANDLE session, void* parameter,
                                      unsigned long parameter_len, unsigned char* associated_data,
                                      unsigned long associated_data_len))
NOT_SUPPORTED(C_EncryptMessageNext, (CK_SESSION_HANDLE session, void* parameter,
                                     unsigned long parameter_len, unsigned char* plaintext_part,
                                     unsigned long plaintext_part_len,
                                     unsigned char* ciphertext_part,
                                     unsigned long* ciphertext_part_len, CK_FLAGS flags))
NOT_SUPPORTED(C_MessageEncryptFinal, (CK_SESSION_HANDLE session))
NOT_SUPPORTED(C_MessageDecryptInit, (CK_SESSION_HANDLE session, CK_MECHANISM* mechanism,
                                     CK_OBJECT_HANDLE key))
NOT_SUPPORTED(C_DecryptMessage, (CK_SESSION_HANDLE session, void* parameter,
                                 unsigned long parameter_len, unsigned char* associated_data,
                                 unsigned long associated_data_len, unsigned char* ciphertext,
                                 unsigned long ciphertext_len, unsigned char* plaintext,
                                 unsigned long* plaintext_len))
NOT_SUPPORTED(C_DecryptMessageBegin, (CK_SESSION_HANDLE session, void* parameter,
                                      unsigned long parameter_len, unsigned char* associated_data,
                                      unsigned long associated_data_len))
NOT_SUPPORTED(C_DecryptMessageNext, (CK_SESSION_HANDLE session, void* parameter,
                                     unsigned long parameter_len, unsigned char* ciphertext_part,
                                     unsigned long ciphertext_part_len,
                                     unsigned char* plaintext_part,
                                     unsigned long* plaintext_part_len, CK_FLAGS flags))
NOT_SUPPORTED(C_MessageDecryptFinal, (CK_SESSION_HANDLE session))
NOT_SUPPORTED(C_MessageSignInit, (CK_SESSION_HANDLE session, CK_MECHANISM* mechanism,
                                  CK_OBJECT_HANDLE key))
NOT_SUPPORTED(C_SignMessage, (CK_SESSION_HANDLE session, void* parameter,
                              unsigned long parameter_len, unsigned char* data,
                              unsigned long data_len, unsigned char* signature,
                              unsigned long* signature_len))
NOT_SUPPORTED(C_SignMessageBegin, (CK_SESSION_HANDLE session, void* parameter,
                                   unsigned long parameter_len))
NOT_SUPPORTED(C_SignMessageNext, (CK_SESSION_HANDLE session, void* parameter,
                                  unsigned long parameter_len, unsigned char* data,
                                  unsigned long data_len, unsigned char* signature,
                                  unsigned long* signature_len))
NOT_SUPPORTED(C_MessageSignFinal, (CK_SESSION_HANDLE session))
NOT_SUPPORTED(C_MessageVerifyInit, (CK_SESSION_HANDLE session, CK_MECHANISM* mechanism,
                                    CK_OBJECT_HANDLE key))
NOT_SUPPORTED(C_VerifyMessage, (CK_SESSION_HANDLE session, void* parameter,
                                unsigned long parameter_len, unsigned char* data,
                                unsigned long data_len, unsigned char* signature,
                                unsigned long signature_len))
NOT_SUPPORTED(C_VerifyMessageBegin, (CK_SESSION_HANDLE session, void* parameter,
                                     unsigned long parameter_len))
NOT_SUPPORTED(C_VerifyMessageNext, (CK_SESSION_HANDLE session, void* parameter,
                                    unsigned long parameter_len, unsigned char* data,
                                    unsigned long data_len, unsigned char* signature,
                                    unsigned long signature_len))
NOT_SUPPORTED(C_MessageVerifyFinal, (CK_SESSION_HANDLE session))

#define FUNCTION_LIST_2_40_FIELDS                                                             \
	.C_Initialize = C_Initialize, .C_Finalize = C_Finalize, .C_GetInfo = C_GetInfo,            \
	.C_GetFunctionList = C_GetFunctionList, .C_GetSlotList = C_GetSlotList,                   \
	.C_GetSlotInfo = C_GetSlotInfo, .C_GetTokenInfo = C_GetTokenInfo,                         \
	.C_GetMechanismList = C_GetMechanismList, .C_GetMechanismInfo = C_GetMechanismInfo,        \
	.C_InitToken = C_InitToken, .C_InitPIN = C_InitPIN, .C_SetPIN = C_SetPIN,                  \
	.C_OpenSession = C_OpenSession, .C_CloseSession = C_CloseSession,                          \
	.C_CloseAllSessions = C_CloseAllSessions, .C_GetSessionInfo = C_GetSessionInfo,            \
	.C_GetOperationState = C_GetOperationState, .C_SetOperationState = C_SetOperationState,    \
	.C_Login = C_Login, .C_Logout = C_Logout, .C_CreateObject = C_CreateObject,                \
	.C_CopyObject = C_CopyObject, .C_DestroyObject = C_DestroyObject,                          \
	.C_GetObjectSize = C_GetObjectSize, .C_GetAttributeValue = C_GetAttributeValue,            \
	.C_SetAttributeValue = C_SetAttributeValue, .C_FindObjectsInit = C_FindObjectsInit,        \
	.C_FindObjects = C_FindObjects, .C_FindObjectsFinal = C_FindObjectsFinal,                  \
	.C_EncryptInit = C_EncryptInit, .C_Encrypt = C_Encrypt,                                    \
	.C_EncryptUpdate = C_EncryptUpdate, .C_EncryptFinal = C_EncryptFinal,                      \
	.C_DecryptInit = C_DecryptInit, .C_Decrypt = C_Decrypt,                                    \
	.C_DecryptUpdate = C_DecryptUpdate, .C_DecryptFinal = C_DecryptFinal,                      \
	.C_DigestInit = C_DigestInit, .C_Digest = C_Digest, .C_DigestUpdate = C_DigestUpdate,      \
	.C_DigestKey = C_DigestKey, .C_DigestFinal = C_DigestFinal, .C_SignInit = C_SignInit,      \
	.C_Sign = C_Sign, .C_SignUpdate = C_SignUpdate, .C_SignFinal = C_SignFinal,                \
	.C_SignRecoverInit = C_SignRecoverInit, .C_SignRecover = C_SignRecover,                    \
	.C_VerifyInit = C_VerifyInit, .C_Verify = C_Verify, .C_VerifyUpdate = C_VerifyUpdate,      \
	.C_VerifyFinal = C_VerifyFinal, .C_VerifyRecoverInit = C_VerifyRecoverInit,                \
	.C_VerifyRecover = C_VerifyRecover, .C_DigestEncryptUpdate = C_DigestEncryptUpdate,        \
	.C_DecryptDigestUpdate = C_DecryptDigestUpdate,                                            \
	.C_SignEncryptUpdate = C_SignEncryptUpdate,                                                \
	.C_DecryptVerifyUpdate = C_DecryptVerifyUpdate, .C_GenerateKey = C_GenerateKey,            \
	.C_GenerateKeyPair = C_GenerateKeyPair, .C_WrapKey = C_WrapKey,                            \
	.C_UnwrapKey = C_UnwrapKey, .C_DeriveKey = C_DeriveKey, .C_SeedRandom = C_SeedRandom,      \
	.C_GenerateRandom = C_GenerateRandom, .C_GetFunctionStatus = C_GetFunctionStatus,          \
	.C_CancelFunction = C_CancelFunction, .C_WaitForSlotEvent = C_WaitForSlotEvent

static CK_FUNCTION_LIST function_list = {
	.version = { 2, 40 },
	FUNCTION_LIST_2_40_FIELDS,
};

/* PKCS#11 3.0 entry points use the same functions and reject unsupported additions. */
static CK_FUNCTION_LIST_3_0 function_list_3_0 = {
	.version = { 3, 0 },
	FUNCTION_LIST_2_40_FIELDS,
	.C_GetInterfaceList = C_GetInterfaceList,
	.C_GetInterface = C_GetInterface,
	.C_LoginUser = C_LoginUser,
	.C_SessionCancel = C_SessionCancel,
	.C_MessageEncryptInit = C_MessageEncryptInit,
	.C_EncryptMessage = C_EncryptMessage,
	.C_EncryptMessageBegin = C_EncryptMessageBegin,
	.C_EncryptMessageNext = C_EncryptMessageNext,
	.C_MessageEncryptFinal = C_MessageEncryptFinal,
	.C_MessageDecryptInit = C_MessageDecryptInit,
	.C_DecryptMessage = C_DecryptMessage,
	.C_DecryptMessageBegin = C_DecryptMessageBegin,
	.C_DecryptMessageNext = C_DecryptMessageNext,
	.C_MessageDecryptFinal = C_MessageDecryptFinal,
	.C_MessageSignInit = C_MessageSignInit,
	.C_SignMessage = C_SignMessage,
	.C_SignMessageBegin = C_SignMessageBegin,
	.C_SignMessageNext = C_SignMessageNext,
	.C_MessageSignFinal = C_MessageSignFinal,
	.C_MessageVerifyInit = C_MessageVerifyInit,
	.C_VerifyMessage = C_VerifyMessage,
	.C_VerifyMessageBegin = C_VerifyMessageBegin,
	.C_VerifyMessageNext = C_VerifyMessageNext,
	.C_MessageVerifyFinal = C_MessageVerifyFinal,
};
