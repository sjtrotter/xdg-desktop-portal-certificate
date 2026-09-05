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

/* A digest, and nothing else, reaches a mechanism that does not hash: 64 bytes
 * of SHA-512, or a 51-byte DigestInfo. The cap is what keeps a caller from
 * buffering a message here in the belief that it will be hashed. */
#define PRE_HASHED_LIMIT 512

/* The 36 bytes of MD5 || SHA1 that TLS 1.0 and 1.1 sign with CKM_RSA_PKCS. It
 * has no hash name the portal will accept, and there is nothing to fall back
 * to; see docs/decisions/0011-client-side-pkcs11-module.md. */
#define TLS10_MD5_SHA1_LENGTH 36

typedef struct
{
	CK_SESSION_HANDLE handle;
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
static gboolean module_initialized;
static PortalClient* module_client;
static PortalGrant* module_grant;
static PortalObjects* module_objects;
static GArray* module_mechanisms;
static guint module_generation;
static GHashTable* module_sessions;
static CK_SESSION_HANDLE module_next_session;
static gboolean module_logged_in;
static gint64 module_refusal_time;
static guint module_refusal_fingerprint;
static char module_serial[PKCS11_PORTAL_TOKEN_SERIAL_SIZE + 1];

/* --------------------------------------------------------------- utilities */

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

static PortalSession* session_lookup(CK_SESSION_HANDLE handle)
{
	if (module_sessions == NULL)
		return NULL;

	return g_hash_table_lookup(module_sessions, GUINT_TO_POINTER(handle));
}

/* ------------------------------------------------------------- grant state */

static void drop_objects(void)
{
	g_clear_pointer(&module_objects, portal_objects_free);
	g_clear_pointer(&module_grant, portal_grant_free);
}

static void release_grant(void)
{
	if (module_grant != NULL && !portal_client_grant_gone(module_client, module_grant))
		portal_client_release(module_client, module_grant);

	drop_objects();
}

static gboolean grant_still_good(void)
{
	if (module_grant == NULL)
		return FALSE;

	if (portal_client_grant_gone(module_client, module_grant))
	{
		g_debug("the grant was invalidated");
		drop_objects();
		return FALSE;
	}

	if (module_grant->expires_at != 0 &&
	    g_get_real_time() / G_USEC_PER_SEC >= module_grant->expires_at)
	{
		g_debug("the grant expired");
		drop_objects();
		return FALSE;
	}

	return TRUE;
}

/** Acquire a credential if this search could use one. Returns FALSE when there
 *  is nothing to search, which is a zero-object answer and never an error. */
static gboolean ensure_grant(CK_ATTRIBUTE_PTR templ, CK_ULONG count)
{
	g_autoptr(GError) error = NULL;
	guint fingerprint;

	if (grant_still_good())
		return TRUE;

	if (!portal_client_available(module_client))
		return FALSE;

	if (!portal_template_wants_credential(templ, count))
		return FALSE;

	fingerprint = portal_template_fingerprint(templ, count);

	if (module_refusal_time != 0)
	{
		gint64 age = g_get_monotonic_time() - module_refusal_time;

		if (fingerprint != module_refusal_fingerprint)
			module_refusal_time = 0;
		else if (age < PKCS11_PORTAL_REFUSAL_GRACE_SECONDS * G_USEC_PER_SEC)
			return FALSE;
		else
			module_refusal_time = 0;
	}

	module_grant = portal_client_acquire(module_client, &error);
	if (module_grant == NULL)
	{
		if (g_error_matches(error, PKCS11_PORTAL_ERROR, PKCS11_PORTAL_ERROR_CANCELLED))
		{
			module_refusal_time = g_get_monotonic_time();
			module_refusal_fingerprint = fingerprint;
		}

		g_debug("no credential: %s", error != NULL ? error->message : "unavailable");
		return FALSE;
	}

	module_objects = portal_objects_new(module_grant, ++module_generation, &error);
	if (module_objects == NULL)
	{
		g_debug("the granted certificate did not become objects");
		release_grant();
		return FALSE;
	}

	return TRUE;
}

/* ----------------------------------------------------------- function lists */

static CK_FUNCTION_LIST function_list;
static CK_FUNCTION_LIST_3_0 function_list_3_0;

#define MODULE_CHECK()                                                                        \
	do                                                                                        \
	{                                                                                         \
		if (!g_atomic_int_get(&module_initialized))                                           \
			return CKR_CRYPTOKI_NOT_INITIALIZED;                                              \
	} while (0)

/* ------------------------------------------------------------- the entries */

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

		if (args->pReserved != NULL)
		{
			g_mutex_unlock(&module_lock);
			return CKR_ARGUMENTS_BAD;
		}

		if (any_mutex && !all_mutex)
		{
			g_mutex_unlock(&module_lock);
			return CKR_ARGUMENTS_BAD;
		}

		/* This module locks with the platform's own primitives. An application
		 * that supplies mutex functions and will not permit that is told so
		 * rather than quietly ignored. */
		if (all_mutex && (args->flags & CKF_OS_LOCKING_OK) == 0)
		{
			g_mutex_unlock(&module_lock);
			return CKR_CANT_LOCK;
		}
	}

	g_snprintf(module_serial, sizeof(module_serial), "%s%013X",
	           PKCS11_PORTAL_TOKEN_SERIAL_PREFIX, (unsigned) (getpid() & 0x1fffffff));

	module_sessions = g_hash_table_new_full(NULL, NULL, NULL, session_free);
	module_next_session = 1;
	module_logged_in = FALSE;
	module_refusal_time = 0;

	if (portal_client_self_excluded())
	{
		g_debug("this process must not load the portal module; no slot will be offered");
	}
	else
	{
		module_client = portal_client_new();
		module_mechanisms = portal_mechanism_list(portal_client_mechanisms(module_client));
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

	release_grant();

	g_clear_pointer(&module_sessions, g_hash_table_unref);
	g_clear_pointer(&module_mechanisms, g_array_unref);
	g_clear_pointer(&module_client, portal_client_free);

	module_logged_in = FALSE;
	g_atomic_int_set(&module_initialized, FALSE);
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
	static CK_INTERFACE interface_list[2];

	if (count == NULL)
		return CKR_ARGUMENTS_BAD;

	interface_list[0].pInterfaceName = (char*) "PKCS 11";
	interface_list[0].pFunctionList = &function_list_3_0;
	interface_list[0].flags = 0;
	interface_list[1].pInterfaceName = (char*) "PKCS 11";
	interface_list[1].pFunctionList = &function_list;
	interface_list[1].flags = 0;

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
	static CK_INTERFACE interface_3_0;
	static CK_INTERFACE interface_2_40;

	if (interface == NULL)
		return CKR_ARGUMENTS_BAD;

	if (interface_name != NULL && strcmp((const char*) interface_name, "PKCS 11") != 0)
		return CKR_ARGUMENTS_BAD;

	/* No fork-safety is claimed, so no flag can be required of it. */
	if (flags != 0)
		return CKR_ARGUMENTS_BAD;

	interface_3_0.pInterfaceName = (char*) "PKCS 11";
	interface_3_0.pFunctionList = &function_list_3_0;
	interface_3_0.flags = 0;
	interface_2_40.pInterfaceName = (char*) "PKCS 11";
	interface_2_40.pFunctionList = &function_list;
	interface_2_40.flags = 0;

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

	/* No portal, no certificate backend, or the experimental gate is off. The
	 * module still loaded and still initialised: an application that loads every
	 * configured module must not break because one of them has nothing to say. */
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
	info->flags = CKF_TOKEN_PRESENT;

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

	/* The PIN is the portal's business and is collected in the backend's own
	 * window, which is exactly what a protected authentication path means to a
	 * consumer: do not ask for one, and do not offer a field. */
	info->flags = CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED |
	              CKF_PROTECTED_AUTHENTICATION_PATH | CKF_USER_PIN_INITIALIZED;

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
	unsigned long available;

	MODULE_CHECK();

	if (count == NULL)
		return CKR_ARGUMENTS_BAD;
	if (slot_id != PORTAL_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	g_mutex_lock(&module_lock);

	if (!portal_client_available(module_client))
	{
		g_mutex_unlock(&module_lock);
		return CKR_TOKEN_NOT_PRESENT;
	}

	available = module_mechanisms != NULL ? module_mechanisms->len : 0;

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
		mechanism_list[i] = g_array_index(module_mechanisms, CK_MECHANISM_TYPE, i);
	*count = available;

	g_mutex_unlock(&module_lock);
	return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slot_id, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO* info)
{
	const PortalMechanism* mechanism;
	CK_RV rv = CKR_OK;

	MODULE_CHECK();

	if (info == NULL)
		return CKR_ARGUMENTS_BAD;
	if (slot_id != PORTAL_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	mechanism = portal_mechanism_lookup(type);

	g_mutex_lock(&module_lock);

	if (!portal_client_available(module_client))
		rv = CKR_TOKEN_NOT_PRESENT;
	else if (mechanism == NULL ||
	         !portal_mechanism_available(mechanism, portal_client_mechanisms(module_client)))
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
	/* Nothing here is writable, so a read/write session would be a promise the
	 * module cannot keep. */
	if ((flags & CKF_RW_SESSION) != 0)
		return CKR_TOKEN_WRITE_PROTECTED;

	g_mutex_lock(&module_lock);

	if (!portal_client_available(module_client))
	{
		g_mutex_unlock(&module_lock);
		return CKR_TOKEN_NOT_PRESENT;
	}

	session = g_new0(PortalSession, 1);
	session->handle = module_next_session++;
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

	/* THE GRANT OUTLIVES THE SESSIONS. GnuTLS opens and closes a session for
	 * every object import and every signature; releasing the grant with the
	 * last session would put the chooser up again for each of them. The grant
	 * ends at C_Finalize, at its own expiry, or when the portal invalidates
	 * it. PKCS#11's login state is per application, so that does end here. */
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

	/* @pin is neither read nor copied nor forwarded. There is no PIN on this
	 * side of the boundary: the portal's backend collects one in its own window
	 * at first private-key use. */
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
	else if (!module_logged_in)
		rv = CKR_USER_NOT_LOGGED_IN;
	else
		module_logged_in = FALSE;

	g_mutex_unlock(&module_lock);

	return rv;
}

/* ---------------------------------------------------------------- searching */

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE session_handle, CK_ATTRIBUTE* templ,
                        unsigned long count)
{
	PortalSession* session;

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

	if (session->find_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_ACTIVE;
	}

	/* THE CHOOSER APPEARS HERE. A search that could be answered by a credential
	 * is the first moment the module knows the application wants one. */
	if (ensure_grant(templ, count))
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
		g_mutex_unlock(&module_lock);
		return CKR_OBJECT_HANDLE_INVALID;
	}

	rv = portal_object_get_attributes(object, templ, count);

	g_mutex_unlock(&module_lock);

	return rv;
}

/* ------------------------------------------------------------------ signing */

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

		/* PKCS#1 permits MGF1 over a different digest; this interface does not,
		 * so a mismatch is refused here rather than sent to be refused there. */
		mgf_hash = portal_mgf_hash(parameters->mgf);
		if (mgf_hash == NULL || strcmp(mgf_hash, hash) != 0)
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

	if (session->sign_buffer->len + size > PRE_HASHED_LIMIT)
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
			/* TLS 1.0 and 1.1 sign MD5 || SHA1 with CKM_RSA_PKCS. There is no
			 * hash name for it and no way to describe it to the portal. */
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
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
	}

	if (session->sign_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_ACTIVE;
	}

	if (!grant_still_good())
	{
		g_mutex_unlock(&module_lock);
		return CKR_KEY_HANDLE_INVALID;
	}

	object = portal_objects_lookup(module_objects, key);
	if (object == NULL || object->object_class != CKO_PRIVATE_KEY)
	{
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

	session = session_lookup(session_handle);
	if (session == NULL)
	{
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
	}

	if (!session->sign_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	/* A size query neither consumes the input nor ends the operation. */
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

	session = session_lookup(session_handle);
	if (session == NULL)
	{
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
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

	session = session_lookup(session_handle);
	if (session == NULL)
	{
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
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

/* --------------------------------------------------------------- decryption */

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

	/* RSA_OAEP and nothing else. A v1.5 decryption would be a Bleichenbacher
	 * oracle over the key on the token, and the portal refuses it too. */
	if (mechanism->mechanism != CKM_RSA_PKCS_OAEP)
		return CKR_MECHANISM_INVALID;

	g_mutex_lock(&module_lock);

	session = session_lookup(session_handle);
	if (session == NULL)
	{
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
	}

	if (session->decrypt_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_ACTIVE;
	}

	if (!grant_still_good())
	{
		g_mutex_unlock(&module_lock);
		return CKR_KEY_HANDLE_INVALID;
	}

	object = portal_objects_lookup(module_objects, key);
	if (object == NULL || object->object_class != CKO_PRIVATE_KEY)
	{
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

	MODULE_CHECK();

	if (plaintext_len == NULL)
		return CKR_ARGUMENTS_BAD;

	g_mutex_lock(&module_lock);

	session = session_lookup(session_handle);
	if (session == NULL)
	{
		g_mutex_unlock(&module_lock);
		return CKR_SESSION_HANDLE_INVALID;
	}

	if (!session->decrypt_active)
	{
		g_mutex_unlock(&module_lock);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	/* The plaintext length is not known until the portal has decrypted, and a
	 * size query must not put a window up, so the modulus size is reported as
	 * the upper bound PKCS#11 permits. */
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
		CK_RV rv = portal_error_to_rv(error);

		session_reset_decrypt(session);
		g_mutex_unlock(&module_lock);
		return rv == CKR_FUNCTION_FAILED ? CKR_ENCRYPTED_DATA_INVALID : rv;
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

/* ------------------------------------------------------------ not supported */

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID* slot, void* reserved)
{
	MODULE_CHECK();

	if ((flags & CKF_DONT_BLOCK) != 0)
		return CKR_NO_EVENT;

	return CKR_FUNCTION_NOT_SUPPORTED;
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

static CK_RV not_supported_3_0(void)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* The 3.0 table exists so that C_GetInterface is not a way past C_GetFunctionList.
 * Everything 3.0 added is refused; the entries are the same functions. */
static CK_FUNCTION_LIST_3_0 function_list_3_0 = {
	.version = { 3, 0 },
	FUNCTION_LIST_2_40_FIELDS,
	.C_GetInterfaceList = C_GetInterfaceList,
	.C_GetInterface = C_GetInterface,
	.C_LoginUser = (CK_C_LoginUser)(void*) not_supported_3_0,
	.C_SessionCancel = (CK_C_SessionCancel)(void*) not_supported_3_0,
	.C_MessageEncryptInit = (CK_C_MessageEncryptInit)(void*) not_supported_3_0,
	.C_EncryptMessage = (CK_C_EncryptMessage)(void*) not_supported_3_0,
	.C_EncryptMessageBegin = (CK_C_EncryptMessageBegin)(void*) not_supported_3_0,
	.C_EncryptMessageNext = (CK_C_EncryptMessageNext)(void*) not_supported_3_0,
	.C_MessageEncryptFinal = (CK_C_MessageEncryptFinal)(void*) not_supported_3_0,
	.C_MessageDecryptInit = (CK_C_MessageDecryptInit)(void*) not_supported_3_0,
	.C_DecryptMessage = (CK_C_DecryptMessage)(void*) not_supported_3_0,
	.C_DecryptMessageBegin = (CK_C_DecryptMessageBegin)(void*) not_supported_3_0,
	.C_DecryptMessageNext = (CK_C_DecryptMessageNext)(void*) not_supported_3_0,
	.C_MessageDecryptFinal = (CK_C_MessageDecryptFinal)(void*) not_supported_3_0,
	.C_MessageSignInit = (CK_C_MessageSignInit)(void*) not_supported_3_0,
	.C_SignMessage = (CK_C_SignMessage)(void*) not_supported_3_0,
	.C_SignMessageBegin = (CK_C_SignMessageBegin)(void*) not_supported_3_0,
	.C_SignMessageNext = (CK_C_SignMessageNext)(void*) not_supported_3_0,
	.C_MessageSignFinal = (CK_C_MessageSignFinal)(void*) not_supported_3_0,
	.C_MessageVerifyInit = (CK_C_MessageVerifyInit)(void*) not_supported_3_0,
	.C_VerifyMessage = (CK_C_VerifyMessage)(void*) not_supported_3_0,
	.C_VerifyMessageBegin = (CK_C_VerifyMessageBegin)(void*) not_supported_3_0,
	.C_VerifyMessageNext = (CK_C_VerifyMessageNext)(void*) not_supported_3_0,
	.C_MessageVerifyFinal = (CK_C_MessageVerifyFinal)(void*) not_supported_3_0,
};
