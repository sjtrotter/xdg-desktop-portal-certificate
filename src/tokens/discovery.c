/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "discovery.h"

#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "../module/constants.h"
#include "../redact.h"

/* How often the presence watcher asks the modules what is in the readers.
 * C_WaitForSlotEvent is optional in PKCS#11 and OpenSC's implementation of the
 * blocking form has historically been unreliable, so this polls instead: it is
 * two ioctls a second against pcscd and it cannot wedge a thread forever. */
#define CERTIFICATE_WATCH_INTERVAL_MS 2000
/* A reader that reports insert and remove repeatedly must not produce a signal
 * storm, so a change has to survive this many consecutive polls. */
#define CERTIFICATE_WATCH_DEBOUNCE 2

struct CertificateTokens
{
	CK_FUNCTION_LIST** modules; /* p11-kit owned, NULL terminated */
	GPtrArray* explicit_modules; /* CK_FUNCTION_LIST*, loaded from --module */
	GHashTable* module_names;    /* CK_FUNCTION_LIST* -> char* (owned), for --module */
	/* THE DEFAULT IS HARDWARE ONLY. See token_skip_reason(). */
	gboolean allow_software;
	GMutex lock;

	/* presence watching */
	GThread* watch_thread;
	GMainContext* watch_context;
	CertificateTokenEvent watch_event;
	gpointer watch_data;
	gboolean watch_stop;
	GPtrArray* watch_known; /* CertificateToken* */
};

/* ------------------------------------------------------------------ tokens */

static CertificateToken* certificate_token_new(void)
{
	CertificateToken* token = g_new0(CertificateToken, 1);

	g_atomic_ref_count_init(&token->ref_count);
	return token;
}

CertificateToken* certificate_token_ref(CertificateToken* token)
{
	g_atomic_ref_count_inc(&token->ref_count);
	return token;
}

void certificate_token_unref(CertificateToken* token)
{
	if (token == NULL)
		return;

	if (!g_atomic_ref_count_dec(&token->ref_count))
		return;

	g_free(token->label);
	g_free(token->manufacturer);
	g_free(token->model);
	g_free(token->serial);
	g_free(token->reader_name);
	g_free(token->module_name);
	g_free(token);
}

gboolean certificate_token_same(const CertificateToken* a, const CertificateToken* b)
{
	if (a == NULL || b == NULL)
		return FALSE;

	/* Slot number is deliberately not part of this. A card reinserted into the
	 * same slot with the same label is a DIFFERENT token until every stable
	 * attribute agrees, and a token with no serial at all is never considered
	 * the same as another observation, because there is nothing to compare. */
	if (a->serial == NULL || *a->serial == '\0')
		return FALSE;

	return g_strcmp0(a->serial, b->serial) == 0 && g_strcmp0(a->label, b->label) == 0 &&
	       g_strcmp0(a->model, b->model) == 0 && g_strcmp0(a->manufacturer, b->manufacturer) == 0;
}

/* PRESENCE, NOT IDENTITY. certificate_token_same() refuses to call a
 * serial-less token the same as any other observation, which is right for
 * re-binding a grant -- there is nothing stable to compare -- and wrong for the
 * watcher, where it made every poll see a change: the two-poll debounce always
 * cleared and such a token produced a TokenRemoved/TokenAdded pair every four
 * seconds forever. Some middleware, and some readers in shared mode, really do
 * report an empty CK_TOKEN_INFO.serialNumber. */
gboolean certificate_token_same_presence(const CertificateToken* a, const CertificateToken* b)
{
	if (a == NULL || b == NULL)
		return FALSE;

	if (a->serial != NULL && *a->serial != '\0')
		return certificate_token_same(a, b);

	if (b->serial != NULL && *b->serial != '\0')
		return FALSE;

	return a->module == b->module && a->slot == b->slot &&
	       g_strcmp0(a->label, b->label) == 0 && g_strcmp0(a->model, b->model) == 0 &&
	       g_strcmp0(a->manufacturer, b->manufacturer) == 0;
}

char* certificate_token_identity(const CertificateToken* token)
{
	return g_strdup_printf("%s\x1f%s\x1f%s\x1f%s", token->manufacturer != NULL ? token->manufacturer : "",
	                       token->model != NULL ? token->model : "",
	                       token->serial != NULL ? token->serial : "",
	                       token->label != NULL ? token->label : "");
}

/* -------------------------------------------------------------- candidates */

static CertificateCandidate* certificate_candidate_new(void)
{
	CertificateCandidate* candidate = g_new0(CertificateCandidate, 1);

	g_atomic_ref_count_init(&candidate->ref_count);
	return candidate;
}

CertificateCandidate* certificate_candidate_ref(CertificateCandidate* candidate)
{
	g_atomic_ref_count_inc(&candidate->ref_count);
	return candidate;
}

void certificate_candidate_unref(CertificateCandidate* candidate)
{
	if (candidate == NULL)
		return;

	if (!g_atomic_ref_count_dec(&candidate->ref_count))
		return;

	g_clear_pointer(&candidate->token, certificate_token_unref);
	g_clear_pointer(&candidate->der, g_byte_array_unref);
	g_clear_pointer(&candidate->cka_id, g_byte_array_unref);
	g_clear_pointer(&candidate->issuer_der, g_byte_array_unref);
	g_free(candidate->certificate_id);
	g_free(candidate->subject_display);
	g_free(candidate->issuer_display);
	g_free(candidate->subject_dn);
	g_strfreev(candidate->eku_oids);
	g_strfreev(candidate->key_usage);
	g_free(candidate->piv_slot);
	g_free(candidate->key_type);
	g_free(candidate->key_curve);
	g_strfreev(candidate->supported_mechanisms);
	g_free(candidate);
}

gboolean certificate_candidate_is_expired(const CertificateCandidate* candidate, gint64 now)
{
	return candidate->not_after > 0 && candidate->not_after < now;
}

gboolean certificate_candidate_is_not_yet_valid(const CertificateCandidate* candidate, gint64 now)
{
	return candidate->not_before > 0 && candidate->not_before > now;
}

static char* certificate_id_for(const GByteArray* der);

/* ------------------------------------------------------------ X.509 parsing */

static char* dn_component(gnutls_x509_crt_t crt, const char* oid, gboolean issuer)
{
	char buffer[512];
	size_t size = sizeof(buffer);
	int rc;

	if (issuer)
		rc = gnutls_x509_crt_get_issuer_dn_by_oid(crt, oid, 0, 0, buffer, &size);
	else
		rc = gnutls_x509_crt_get_dn_by_oid(crt, oid, 0, 0, buffer, &size);

	if (rc < 0)
		return NULL;

	return g_utf8_make_valid(buffer, -1);
}

static char* dn_full(gnutls_x509_crt_t crt, gboolean issuer)
{
	gnutls_datum_t datum = { NULL, 0 };
	char* text = NULL;
	int rc;

	if (issuer)
		rc = gnutls_x509_crt_get_issuer_dn3(crt, &datum, 0);
	else
		rc = gnutls_x509_crt_get_dn3(crt, &datum, 0);

	if (rc < 0)
		return NULL;

	text = g_utf8_make_valid((const char*) datum.data, datum.size);
	gnutls_free(datum.data);
	return text;
}

/* The name shown in the chooser row. CN when there is one, otherwise the whole
 * DN, otherwise an honest placeholder -- never a guess and never empty, because
 * an empty row is a row the user cannot tell apart from another empty row. */
static char* display_name(gnutls_x509_crt_t crt, gboolean issuer)
{
	char* name = dn_component(crt, GNUTLS_OID_X520_COMMON_NAME, issuer);

	if (name != NULL && *name != '\0')
		return name;
	g_free(name);

	name = dn_component(crt, GNUTLS_OID_X520_ORGANIZATION_NAME, issuer);
	if (name != NULL && *name != '\0')
		return name;
	g_free(name);

	name = dn_full(crt, issuer);
	if (name != NULL && *name != '\0')
		return name;
	g_free(name);

	return g_strdup(issuer ? "Unnamed issuer" : "Unnamed certificate");
}

static char** parse_eku(gnutls_x509_crt_t crt)
{
	g_autoptr(GStrvBuilder) builder = g_strv_builder_new();
	gboolean any = FALSE;

	for (unsigned i = 0;; i++)
	{
		char buffer[128];
		size_t size = sizeof(buffer);
		unsigned critical = 0;
		int rc;

		rc = gnutls_x509_crt_get_key_purpose_oid(crt, i, buffer, &size, &critical);
		if (rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;
		if (rc < 0)
			break;

		any = TRUE;
		g_strv_builder_add(builder, buffer);
	}

	/* NULL means "this certificate has no extended key usage extension", which
	 * is a different fact from "it has one and it is empty". The purpose rules
	 * in tokens/filter.c turn on exactly that difference. */
	if (!any)
		return NULL;

	return g_strv_builder_end(builder);
}

static char** parse_key_usage(gnutls_x509_crt_t crt)
{
	g_autoptr(GStrvBuilder) builder = g_strv_builder_new();
	unsigned int usage = 0;
	unsigned int critical = 0;

	if (gnutls_x509_crt_get_key_usage(crt, &usage, &critical) < 0)
		return NULL;

	/* The names are the ones the public interface's certificate_filter uses. */
	if (usage & GNUTLS_KEY_DIGITAL_SIGNATURE)
		g_strv_builder_add(builder, "digital_signature");
	if (usage & GNUTLS_KEY_NON_REPUDIATION)
		g_strv_builder_add(builder, "content_commitment");
	if (usage & GNUTLS_KEY_KEY_ENCIPHERMENT)
		g_strv_builder_add(builder, "key_encipherment");
	if (usage & GNUTLS_KEY_DATA_ENCIPHERMENT)
		g_strv_builder_add(builder, "data_encipherment");
	if (usage & GNUTLS_KEY_KEY_AGREEMENT)
		g_strv_builder_add(builder, "key_agreement");
	if (usage & GNUTLS_KEY_KEY_CERT_SIGN)
		g_strv_builder_add(builder, "key_cert_sign");
	if (usage & GNUTLS_KEY_CRL_SIGN)
		g_strv_builder_add(builder, "crl_sign");

	return g_strv_builder_end(builder);
}

static gboolean certificate_parse_der(const guint8* der, gsize length,
                                      CertificateCandidate* out, GError** error)
{
	gnutls_x509_crt_t crt = NULL;
	gnutls_datum_t datum = { (unsigned char*) der, (unsigned int) length };
	gnutls_datum_t issuer = { NULL, 0 };
	int rc;
	unsigned int bits = 0;

	rc = gnutls_x509_crt_init(&crt);
	if (rc < 0)
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "Could not allocate a certificate");
		return FALSE;
	}

	rc = gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_DER);
	if (rc < 0)
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		                    "Not a valid X.509 certificate");
		gnutls_x509_crt_deinit(crt);
		return FALSE;
	}

	out->subject_display = display_name(crt, FALSE);
	out->issuer_display = display_name(crt, TRUE);
	out->subject_dn = dn_full(crt, FALSE);
	out->not_before = (gint64) gnutls_x509_crt_get_activation_time(crt);
	out->not_after = (gint64) gnutls_x509_crt_get_expiration_time(crt);
	out->eku_oids = parse_eku(crt);
	out->key_usage = parse_key_usage(crt);

	if (gnutls_x509_crt_get_raw_issuer_dn(crt, &issuer) >= 0)
	{
		out->issuer_der = g_byte_array_sized_new(issuer.size);
		g_byte_array_append(out->issuer_der, issuer.data, issuer.size);
		gnutls_free(issuer.data);
	}

	rc = gnutls_x509_crt_get_pk_algorithm(crt, &bits);
	if (rc == GNUTLS_PK_RSA || rc == GNUTLS_PK_RSA_PSS)
	{
		out->key_type = g_strdup("RSA");
		out->key_size = (guint) bits;
	}
	else if (rc == GNUTLS_PK_ECDSA)
	{
		gnutls_ecc_curve_t curve = GNUTLS_ECC_CURVE_INVALID;
		gnutls_datum_t x = { NULL, 0 };
		gnutls_datum_t y = { NULL, 0 };

		out->key_type = g_strdup("EC");
		out->key_size = (guint) bits;

		if (gnutls_x509_crt_get_pk_ecc_raw(crt, &curve, &x, &y) >= 0)
		{
			const char* name = gnutls_ecc_curve_get_name(curve);

			if (name != NULL)
				out->key_curve = g_strdup(name);
			gnutls_free(x.data);
			gnutls_free(y.data);
		}
	}
	else
	{
		/* A key this backend has no mechanism for. It is not an error: the
		 * certificate is simply never a candidate, and saying so honestly beats
		 * guessing a type. */
		out->key_type = g_strdup("unsupported");
		out->key_size = (guint) MAX(bits, 0);
	}

	gnutls_x509_crt_deinit(crt);
	return TRUE;
}

CertificateCandidate* certificate_candidate_new_from_der(const guint8* der, gsize length,
                                                         GError** error)
{
	g_autoptr(CertificateCandidate) candidate = certificate_candidate_new();

	candidate->der = g_byte_array_sized_new(length);
	g_byte_array_append(candidate->der, der, length);
	candidate->certificate_id = certificate_id_for(candidate->der);

	if (!certificate_parse_der(der, length, candidate, error))
		return NULL;

	return g_steal_pointer(&candidate);
}

/* --------------------------------------------------------------- PIV slots */

/* Best effort, and marked as such everywhere it is used. OpenSC's PIV driver
 * uses the PIV key reference as CKA_ID on some cards (0x9a, 0x9c, 0x9d, 0x9e)
 * and a 1-based index on others (0x01..0x04). Anything else yields NULL rather
 * than a guess, because a wrong slot name in a filter silently hides the
 * certificate the user wanted. */
static char* piv_slot_from_id(const GByteArray* cka_id)
{
	if (cka_id == NULL || cka_id->len != 1)
		return NULL;

	switch (cka_id->data[0])
	{
		case 0x9a:
		case 0x01:
			return g_strdup("authentication");
		case 0x9c:
		case 0x02:
			return g_strdup("signature");
		case 0x9d:
		case 0x03:
			return g_strdup("key_management");
		case 0x9e:
		case 0x04:
			return g_strdup("card_authentication");
		default:
			return NULL;
	}
}

/* ------------------------------------------------------------ module loading */

gboolean certificate_module_is_portal_module(const char* name, const char* filename)
{
	if (name != NULL && g_ascii_strcasecmp(name, PKCS11_PORTAL_MODULE_NAME) == 0)
		return TRUE;

	if (filename != NULL)
	{
		g_autofree char* base = g_path_get_basename(filename);

		if (g_ascii_strcasecmp(base, PKCS11_PORTAL_MODULE_BASENAME) == 0)
			return TRUE;
		if (g_ascii_strcasecmp(base, "lib" PKCS11_PORTAL_MODULE_BASENAME) == 0)
			return TRUE;
	}

	return FALSE;
}

static gboolean module_is_interesting(CK_FUNCTION_LIST* module)
{
	g_autofree char* name = p11_kit_module_get_name(module);
	g_autofree char* filename = p11_kit_module_get_filename(module);

	if (certificate_module_is_portal_module(name, filename))
		return FALSE;

	if (name == NULL)
		return TRUE;

	/* p11-kit's own trust module holds CA certificates and no private keys, so
	 * it can never produce a candidate; enumerating it costs seconds on a
	 * machine with a large trust store. gnome-keyring's module holds software
	 * keys the user never put on a token, and offering them in a window that
	 * says "security token" would be a lie. Either can be brought back with an
	 * explicit --module. */
	if (g_ascii_strcasecmp(name, "p11-kit-trust") == 0)
		return FALSE;
	if (g_ascii_strcasecmp(name, "gnome-keyring") == 0)
		return FALSE;

	return TRUE;
}

CertificateTokens* certificate_tokens_new(const char* const* module_paths, GError** error)
{
	CertificateTokens* tokens = g_new0(CertificateTokens, 1);

	g_mutex_init(&tokens->lock);
	tokens->explicit_modules = g_ptr_array_new();
	tokens->module_names = g_hash_table_new_full(NULL, NULL, NULL, g_free);

	if (module_paths != NULL && module_paths[0] != NULL)
	{
		for (gsize i = 0; module_paths[i] != NULL; i++)
		{
			CK_FUNCTION_LIST* module = NULL;
			CK_RV rv;

			if (certificate_module_is_portal_module(NULL, module_paths[i]))
			{
				g_set_error(error, CERTIFICATE_PKCS11_ERROR,
				            CERTIFICATE_PKCS11_ERROR_NOT_SUPPORTED,
				            "'%s' is the portal's own client-side module and this backend "
				            "would recurse into the portal by loading it",
				            module_paths[i]);
				certificate_tokens_free(tokens);
				return NULL;
			}

			module = p11_kit_module_load(module_paths[i], 0);
			if (module == NULL)
			{
				g_autofree char* text = certificate_redact_error_text(p11_kit_message());

				g_set_error(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
				            "Could not load the PKCS#11 module '%s': %s", module_paths[i], text);
				certificate_tokens_free(tokens);
				return NULL;
			}

			rv = p11_kit_module_initialize(module);
			if (rv != CKR_OK)
			{
				certificate_pkcs11_set_error(error, rv, "C_Initialize");
				p11_kit_module_release(module);
				certificate_tokens_free(tokens);
				return NULL;
			}

			g_ptr_array_add(tokens->explicit_modules, module);
			g_hash_table_insert(tokens->module_names, module,
			                    g_path_get_basename(module_paths[i]));
		}

		return tokens;
	}

	/* Managed modules, so that p11-kit owns the C_Initialize refcounting and
	 * two consumers in one process cannot finalize each other's module. */
	tokens->modules = p11_kit_modules_load_and_initialize(0);
	if (tokens->modules == NULL)
	{
		g_autofree char* text = certificate_redact_error_text(p11_kit_message());

		g_set_error(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_FAILED,
		            "Could not load the configured PKCS#11 modules: %s", text);
		certificate_tokens_free(tokens);
		return NULL;
	}

	return tokens;
}

void certificate_tokens_free(CertificateTokens* tokens)
{
	if (tokens == NULL)
		return;

	certificate_tokens_stop_watch(tokens);

	if (tokens->modules != NULL)
		p11_kit_modules_finalize_and_release(tokens->modules);

	for (guint i = 0; i < tokens->explicit_modules->len; i++)
	{
		CK_FUNCTION_LIST* module = g_ptr_array_index(tokens->explicit_modules, i);

		p11_kit_module_finalize(module);
		p11_kit_module_release(module);
	}
	g_ptr_array_free(tokens->explicit_modules, TRUE);
	g_clear_pointer(&tokens->module_names, g_hash_table_unref);

	g_clear_pointer(&tokens->watch_known, g_ptr_array_unref);
	g_mutex_clear(&tokens->lock);
	g_free(tokens);
}

void certificate_tokens_set_allow_software(CertificateTokens* tokens, gboolean allow)
{
	g_mutex_lock(&tokens->lock);
	tokens->allow_software = allow;
	g_mutex_unlock(&tokens->lock);
}

/* Every module this backend should look at, explicit or configured. */
static GPtrArray* module_list(CertificateTokens* tokens)
{
	GPtrArray* list = g_ptr_array_new();

	for (guint i = 0; i < tokens->explicit_modules->len; i++)
		g_ptr_array_add(list, g_ptr_array_index(tokens->explicit_modules, i));

	if (tokens->modules != NULL)
	{
		for (gsize i = 0; tokens->modules[i] != NULL; i++)
		{
			if (module_is_interesting(tokens->modules[i]))
				g_ptr_array_add(list, tokens->modules[i]);
		}
	}

	return list;
}

/* ------------------------------------------------------------- enumeration */

static CertificateToken* token_from_slot(CertificateTokens* tokens, CK_FUNCTION_LIST* module,
                                        CK_SLOT_ID slot)
{
	CK_TOKEN_INFO token_info;
	CK_SLOT_INFO slot_info;
	CertificateToken* token = NULL;

	memset(&token_info, 0, sizeof(token_info));
	memset(&slot_info, 0, sizeof(slot_info));

	if (module->C_GetTokenInfo(slot, &token_info) != CKR_OK)
		return NULL;

	/* A slot that reports a token which has never been initialised is a slot
	 * with nothing on it. SoftHSM always presents one; a reader with no card
	 * does not get this far. Listing it would tell the user they have a token
	 * they do not have. */
	if ((token_info.flags & CKF_TOKEN_INITIALIZED) == 0)
		return NULL;

	token = certificate_token_new();
	token->module = module;
	token->slot = slot;
	token->label = certificate_pkcs11_string(token_info.label, sizeof(token_info.label));
	token->manufacturer =
	    certificate_pkcs11_string(token_info.manufacturerID, sizeof(token_info.manufacturerID));
	token->model = certificate_pkcs11_string(token_info.model, sizeof(token_info.model));
	token->serial =
	    certificate_pkcs11_string(token_info.serialNumber, sizeof(token_info.serialNumber));
	token->module_name = p11_kit_module_get_name(module);
	if (token->module_name == NULL && tokens != NULL)
	{
		const char* name = g_hash_table_lookup(tokens->module_names, module);

		token->module_name = g_strdup(name != NULL ? name : "(unnamed module)");
	}

	if (module->C_GetSlotInfo(slot, &slot_info) == CKR_OK)
	{
		token->reader_name =
		    certificate_pkcs11_string(slot_info.slotDescription, sizeof(slot_info.slotDescription));

		/* CKF_HW_SLOT, ON THE *SLOT*, is PKCS#11's only answer to "is this a
		 * hardware device". It is worth naming the trap: CK_TOKEN_INFO has no
		 * such flag, and the constant called CKF_HW is (1<<0) in the MECHANISM
		 * flags -- the same bit that means CKF_RNG in CK_TOKEN_INFO.flags.
		 * Testing token_info.flags & CKF_HW therefore asks "does this token
		 * have a random number generator", which SoftHSM answers yes to. This
		 * code asked exactly that question for one draft; see
		 * token_skip_reason(). */
		token->hardware = (slot_info.flags & CKF_HW_SLOT) != 0;
	}
	else
	{
		token->reader_name = g_strdup("");
	}

	token->module_named_explicitly =
	    tokens != NULL && g_hash_table_contains(tokens->module_names, module);

	token->protected_authentication_path =
	    (token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0;
	token->login_required = (token_info.flags & CKF_LOGIN_REQUIRED) != 0;
	token->pin_count_low = (token_info.flags & CKF_USER_PIN_COUNT_LOW) != 0;
	token->pin_final_try = (token_info.flags & CKF_USER_PIN_FINAL_TRY) != 0;
	token->pin_locked = (token_info.flags & CKF_USER_PIN_LOCKED) != 0;

	return token;
}

/* WHY THIS TOKEN IS NOT OFFERED, or NULL when it is. One predicate, used by
 * every enumeration in this file, so that a token can never be listed by one
 * path and refused by another.
 *
 * THE DEFAULT IS HARDWARE ONLY, and it is a default about HONESTY rather than
 * about strength. p11-kit on an ordinary GNOME machine presents software key
 * stores as tokens -- gnome-keyring's module is the one that started this --
 * and a window headed "security token" that offers keys sitting in the user's
 * home directory is a window telling the user something untrue about where
 * their key is. CKF_HW is the only bit PKCS#11 has on the question. It is a
 * claim by the module, not a fact anything can check, so this is a default and
 * NOT a security boundary: a module that lies about CKF_HW is a module that was
 * already loaded into this process.
 *
 * TWO WAYS PAST IT, both deliberate acts:
 *
 *   --allow-software-tokens   offer them anyway, everywhere.
 *   --module PATH             the operator named this module. Naming a module
 *                             is already saying "use this one", and the tests
 *                             and tools/ point --module at SoftHSM; making them
 *                             say it twice would add a flag and no decision.
 *                             p11-kit's CONFIGURED set is "whatever this machine
 *                             happens to have", which is the set the default is
 *                             about. */
static const char* token_skip_reason(const CertificateTokens* tokens,
                                     const CertificateToken* token)
{
	/* p11-kit's trust module is skipped by name in module_is_interesting();
	 * this catches a trust token reached through an explicit --module, and any
	 * other module that decided to present itself with that model string. */
	if (g_strcmp0(token->model, CERTIFICATE_P11_KIT_TRUST_MODEL) == 0)
		return "trust store: it holds CA certificates, never a private key";

	if (token->hardware || token->module_named_explicitly)
		return NULL;

	if (tokens != NULL && tokens->allow_software)
		return NULL;

	return "not a hardware token (the slot does not set CKF_HW_SLOT); pass "
	       "--allow-software-tokens or --module to use it";
}

static GPtrArray* slots_with_token(CK_FUNCTION_LIST* module)
{
	GPtrArray* slots = g_ptr_array_new();
	g_autofree CK_SLOT_ID* ids = NULL;
	CK_ULONG count = 0;

	if (module->C_GetSlotList(CK_TRUE, NULL, &count) != CKR_OK || count == 0)
		return slots;

	ids = g_new0(CK_SLOT_ID, count);
	if (module->C_GetSlotList(CK_TRUE, ids, &count) != CKR_OK)
		return slots;

	for (CK_ULONG i = 0; i < count; i++)
		g_ptr_array_add(slots, GSIZE_TO_POINTER((gsize) ids[i]));

	return slots;
}

static char* certificate_id_for(const GByteArray* der)
{
	return g_compute_checksum_for_data(G_CHECKSUM_SHA256, der->data, der->len);
}

static char** mechanisms_for(CK_FUNCTION_LIST* module, CK_SLOT_ID slot, const char* key_type)
{
	g_autoptr(GStrvBuilder) builder = g_strv_builder_new();

	/* The names are the frontend's; the frontend intersects this with its own
	 * allow list, so a mechanism named here that the portal does not permit is
	 * dropped rather than honoured. */
	if (g_strcmp0(key_type, "RSA") == 0)
	{
		if (certificate_pkcs11_has_mechanism(module, slot, CKM_RSA_PKCS))
			g_strv_builder_add(builder, "RSA_PKCS1_V1_5");
		if (certificate_pkcs11_has_mechanism(module, slot, CKM_RSA_PKCS_PSS))
			g_strv_builder_add(builder, "RSA_PSS");
		/* Decryption only, and only where the token really has it. A card that
		 * cannot do OAEP must not be offered for a Decrypt grant: the
		 * interface has no other decryption mechanism, so the alternative is a
		 * grant that says it may decrypt and fails at the first attempt. */
		if (certificate_pkcs11_has_mechanism(module, slot, CKM_RSA_PKCS_OAEP))
			g_strv_builder_add(builder, "RSA_OAEP");
	}
	else if (g_strcmp0(key_type, "EC") == 0)
	{
		if (certificate_pkcs11_has_mechanism(module, slot, CKM_ECDSA))
			g_strv_builder_add(builder, "ECDSA");
	}

	return g_strv_builder_end(builder);
}

static void enumerate_token(CK_FUNCTION_LIST* module, CertificateToken* token, GPtrArray* out,
                            GCancellable* cancellable)
{
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS certificate_class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE x509 = CKC_X_509;
	CK_ATTRIBUTE template_[] = {
		{ CKA_CLASS, &certificate_class, sizeof(certificate_class) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof(x509) },
	};
	g_autoptr(GError) local_error = NULL;
	g_autoptr(GArray) handles = NULL;
	CK_RV rv;

	rv = module->C_OpenSession(token->slot, CKF_SERIAL_SESSION, NULL, NULL, &session);
	if (rv != CKR_OK)
	{
		/* One unopenable slot takes that token out of the answer and leaves
		 * every other token in it. A wedged reader is not a reason to tell the
		 * user they have no cards. */
		certificate_log_debug(CERTIFICATE_REASON_DISCOVERY_RESULT, "slot-open-failed");
		return;
	}

	handles = certificate_pkcs11_find_objects(module, session, template_, G_N_ELEMENTS(template_),
	                                          &local_error);
	if (handles == NULL)
	{
		/* A token holding no matching object reports failure with no output.
		 * That is not an error and must not abort discovery. */
		certificate_log_debug(CERTIFICATE_REASON_DISCOVERY_RESULT, "find-objects-failed");
		module->C_CloseSession(session);
		return;
	}

	for (guint i = 0; i < handles->len; i++)
	{
		CK_OBJECT_HANDLE handle = g_array_index(handles, CK_OBJECT_HANDLE, i);
		g_autoptr(GByteArray) der = NULL;
		g_autoptr(GByteArray) cka_id = NULL;
		g_autoptr(CertificateCandidate) candidate = NULL;
		g_autoptr(GError) parse_error = NULL;
		CK_OBJECT_CLASS private_class = CKO_PRIVATE_KEY;
		CK_OBJECT_CLASS public_class = CKO_PUBLIC_KEY;
		CK_ATTRIBUTE key_template[2];
		g_autoptr(GArray) keys = NULL;
		g_autoptr(GArray) public_keys = NULL;
		CK_ULONG key_count = 0;

		if (g_cancellable_is_cancelled(cancellable))
			break;

		der = certificate_pkcs11_get_attribute(module, session, handle, CKA_VALUE);
		if (der == NULL || der->len == 0)
			continue;

		cka_id = certificate_pkcs11_get_attribute(module, session, handle, CKA_ID);
		if (cka_id == NULL || cka_id->len == 0)
		{
			/* Without a CKA_ID there is no way to find the private key that
			 * goes with this certificate, so it can never be used. */
			continue;
		}

		/* A certificate with no matching key on the same token is a certificate
		 * this backend cannot sign with, so it is not a candidate -- offering it
		 * would produce a chooser row that fails at Sign.
		 *
		 * THE SESSION IS NOT LOGGED IN HERE, on purpose: enumerating what is on
		 * a card must not spend the user's presence. On most tokens the private
		 * key OBJECT is still visible (its value is not), which is what PIV
		 * cards through OpenSC do. On tokens where CKA_PRIVATE hides it --
		 * SoftHSM, and some middleware -- the matching PUBLIC key stands in as
		 * proof that a key pair with this id exists, and failing that, a token
		 * that says CKF_LOGIN_REQUIRED is given the benefit of the doubt rather
		 * than reporting the card as empty. Which of the three happened decides
		 * how can_sign and can_decrypt are established. */
		key_count = 0;
		key_template[key_count].type = CKA_CLASS;
		key_template[key_count].pValue = &private_class;
		key_template[key_count].ulValueLen = sizeof(private_class);
		key_count++;
		key_template[key_count].type = CKA_ID;
		key_template[key_count].pValue = cka_id->data;
		key_template[key_count].ulValueLen = cka_id->len;
		key_count++;

		keys = certificate_pkcs11_find_objects(module, session, key_template, key_count, NULL);
		if (keys == NULL || keys->len == 0)
		{
			g_clear_pointer(&keys, g_array_unref);

			key_template[0].pValue = &public_class;
			key_template[0].ulValueLen = sizeof(public_class);
			public_keys =
			    certificate_pkcs11_find_objects(module, session, key_template, key_count, NULL);

			if ((public_keys == NULL || public_keys->len == 0) && !token->login_required)
				continue;
		}

		candidate = certificate_candidate_new();
		candidate->token = certificate_token_ref(token);
		candidate->der = g_byte_array_ref(der);
		candidate->cka_id = g_byte_array_ref(cka_id);
		candidate->certificate_id = certificate_id_for(der);

		if (!certificate_parse_der(der->data, der->len, candidate, &parse_error))
		{
			certificate_log_debug(CERTIFICATE_REASON_DISCOVERY_RESULT, "certificate-unparseable");
			continue;
		}

		candidate->piv_slot = piv_slot_from_id(cka_id);

		/* CKA_SIGN and CKA_DECRYPT are read off the PRIVATE KEY where it can be
		 * seen, not guessed from the certificate's key usage: the card is the
		 * authority on what its key will do. Where it cannot be seen, the
		 * public key's CKA_VERIFY and CKA_ENCRYPT are the closest honest
		 * answer, and where neither can be seen the certificate's own key usage
		 * is -- which is why the grant re-checks everything at Sign time
		 * against the key it actually opened. */
		if (keys != NULL && keys->len > 0)
		{
			CK_OBJECT_HANDLE key = g_array_index(keys, CK_OBJECT_HANDLE, 0);

			candidate->can_sign =
			    certificate_pkcs11_get_bool(module, session, key, CKA_SIGN, TRUE);
			candidate->can_decrypt =
			    certificate_pkcs11_get_bool(module, session, key, CKA_DECRYPT, FALSE);
		}
		else if (public_keys != NULL && public_keys->len > 0)
		{
			CK_OBJECT_HANDLE key = g_array_index(public_keys, CK_OBJECT_HANDLE, 0);

			candidate->can_sign =
			    certificate_pkcs11_get_bool(module, session, key, CKA_VERIFY, TRUE);
			candidate->can_decrypt =
			    certificate_pkcs11_get_bool(module, session, key, CKA_ENCRYPT, FALSE);
		}
		else
		{
			const char* const* usage = (const char* const*) candidate->key_usage;

			/* No key usage extension means the key is restricted by none, so
			 * both answers are yes. Where there is one it decides both: a
			 * keyEncipherment-only key-management certificate must not come
			 * out of here claiming it will sign. */
			candidate->can_sign = usage == NULL || g_strv_contains(usage, "digital_signature") ||
			                      g_strv_contains(usage, "content_commitment");
			candidate->can_decrypt = usage == NULL || g_strv_contains(usage, "key_encipherment") ||
			                         g_strv_contains(usage, "data_encipherment");
		}

		candidate->supported_mechanisms = mechanisms_for(module, token->slot, candidate->key_type);
		if (candidate->supported_mechanisms == NULL || candidate->supported_mechanisms[0] == NULL)
		{
			/* No mechanism this portal knows -- a DSA or Ed25519 key, say.
			 * Never offered, because the grant would be empty. */
			continue;
		}

		g_ptr_array_add(out, g_steal_pointer(&candidate));
	}

	module->C_CloseSession(session);
}

GPtrArray* certificate_tokens_enumerate(CertificateTokens* tokens, GCancellable* cancellable,
                                        GError** error)
{
	GPtrArray* candidates = g_ptr_array_new_with_free_func((GDestroyNotify) certificate_candidate_unref);
	g_autoptr(GPtrArray) modules = NULL;
	guint token_count = 0;

	g_mutex_lock(&tokens->lock);
	modules = module_list(tokens);

	for (guint m = 0; m < modules->len; m++)
	{
		CK_FUNCTION_LIST* module = g_ptr_array_index(modules, m);
		g_autoptr(GPtrArray) slots = slots_with_token(module);

		for (guint s = 0; s < slots->len; s++)
		{
			CK_SLOT_ID slot = (CK_SLOT_ID) GPOINTER_TO_SIZE(g_ptr_array_index(slots, s));
			g_autoptr(CertificateToken) token = NULL;

			if (g_cancellable_is_cancelled(cancellable))
			{
				g_mutex_unlock(&tokens->lock);
				g_ptr_array_unref(candidates);
				g_cancellable_set_error_if_cancelled(cancellable, error);
				return NULL;
			}

			token = token_from_slot(tokens, module, slot);
			if (token == NULL)
				continue;

			if (token_skip_reason(tokens, token) != NULL)
				continue;

			token_count++;
			enumerate_token(module, token, candidates, cancellable);
		}
	}
	g_mutex_unlock(&tokens->lock);

	certificate_log_counts(CERTIFICATE_REASON_DISCOVERY_RESULT, token_count, candidates->len);
	return candidates;
}

typedef struct
{
	CertificateTokens* tokens;
} EnumerateData;

static void enumerate_thread(GTask* task, gpointer source, gpointer task_data,
                             GCancellable* cancellable)
{
	EnumerateData* data = task_data;
	g_autoptr(GError) error = NULL;
	GPtrArray* candidates = NULL;

	candidates = certificate_tokens_enumerate(data->tokens, cancellable, &error);
	if (candidates == NULL)
		g_task_return_error(task, g_steal_pointer(&error));
	else
		g_task_return_pointer(task, candidates, (GDestroyNotify) g_ptr_array_unref);
}

void certificate_tokens_enumerate_async(CertificateTokens* tokens, GCancellable* cancellable,
                                        GAsyncReadyCallback callback, gpointer user_data)
{
	g_autoptr(GTask) task = NULL;
	EnumerateData* data = g_new0(EnumerateData, 1);

	data->tokens = tokens;

	task = g_task_new(NULL, cancellable, callback, user_data);
	g_task_set_source_tag(task, certificate_tokens_enumerate_async);
	g_task_set_task_data(task, data, g_free);
	/* Never on the main thread: loading a certificate off a card can take
	 * seconds, and the window that is about to appear has to stay responsive. */
	g_task_run_in_thread(task, enumerate_thread);
}

GPtrArray* certificate_tokens_enumerate_finish(CertificateTokens* tokens, GAsyncResult* result,
                                               GError** error)
{
	return g_task_propagate_pointer(G_TASK(result), error);
}

/* @include_skipped is TRUE only for --list-tokens, which has to be able to say
 * "there IS a token here and this is why it is not being offered". Everything
 * else -- the presence watcher included -- gets the tokens this backend will
 * actually use, because a TokenAdded for a token no grant could ever name is a
 * signal about nothing. */
static GPtrArray* list_tokens(CertificateTokens* tokens, gboolean include_skipped)
{
	GPtrArray* list = g_ptr_array_new_with_free_func((GDestroyNotify) certificate_token_unref);
	g_autoptr(GPtrArray) modules = NULL;

	g_mutex_lock(&tokens->lock);
	modules = module_list(tokens);

	for (guint m = 0; m < modules->len; m++)
	{
		CK_FUNCTION_LIST* module = g_ptr_array_index(modules, m);
		g_autoptr(GPtrArray) slots = slots_with_token(module);

		for (guint s = 0; s < slots->len; s++)
		{
			CK_SLOT_ID slot = (CK_SLOT_ID) GPOINTER_TO_SIZE(g_ptr_array_index(slots, s));
			CertificateToken* token = token_from_slot(tokens, module, slot);

			if (token == NULL)
				continue;

			token->skip_reason = token_skip_reason(tokens, token);

			if (token->skip_reason != NULL && !include_skipped)
			{
				certificate_token_unref(token);
				continue;
			}

			g_ptr_array_add(list, token);
		}
	}
	g_mutex_unlock(&tokens->lock);

	return list;
}

GPtrArray* certificate_tokens_list(CertificateTokens* tokens, GError** error)
{
	return list_tokens(tokens, FALSE);
}

GPtrArray* certificate_tokens_list_all(CertificateTokens* tokens, GError** error)
{
	return list_tokens(tokens, TRUE);
}

gboolean certificate_tokens_open_session(CertificateTokens* tokens, const CertificateToken* token,
                                         CK_FUNCTION_LIST** module_out,
                                         CK_SESSION_HANDLE* session_out, GError** error)
{
	g_autoptr(GPtrArray) modules = NULL;
	gboolean found = FALSE;

	g_mutex_lock(&tokens->lock);
	modules = module_list(tokens);

	for (guint m = 0; m < modules->len && !found; m++)
	{
		CK_FUNCTION_LIST* module = g_ptr_array_index(modules, m);
		g_autoptr(GPtrArray) slots = slots_with_token(module);

		for (guint s = 0; s < slots->len; s++)
		{
			CK_SLOT_ID slot = (CK_SLOT_ID) GPOINTER_TO_SIZE(g_ptr_array_index(slots, s));
			g_autoptr(CertificateToken) present = token_from_slot(tokens, module, slot);
			CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
			CK_RV rv;

			/* The slot number the token was FOUND at is not how it is looked up
			 * again. A different card in the same slot is a different token. */
			if (present == NULL || !certificate_token_same(present, token))
				continue;

			/* BELT TO THE BRACES. Nothing can hold a grant on a token that was
			 * never enumerated, so this cannot fire today; it is here so that
			 * "which tokens may be used" has exactly one answer in this file. */
			if (token_skip_reason(tokens, present) != NULL)
				continue;

			rv = module->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &session);
			if (rv != CKR_OK)
			{
				certificate_pkcs11_set_error(error, rv, "C_OpenSession");
				g_mutex_unlock(&tokens->lock);
				return FALSE;
			}

			*module_out = module;
			*session_out = session;
			found = TRUE;
			break;
		}
	}
	g_mutex_unlock(&tokens->lock);

	if (!found)
	{
		g_set_error_literal(error, CERTIFICATE_PKCS11_ERROR, CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED,
		                    "The security token is no longer present");
		return FALSE;
	}

	return TRUE;
}

void certificate_tokens_refresh_flags(CertificateTokens* tokens, CertificateToken* token)
{
	g_autoptr(GPtrArray) modules = NULL;

	if (tokens == NULL || token == NULL)
		return;

	g_mutex_lock(&tokens->lock);
	modules = module_list(tokens);

	for (guint m = 0; m < modules->len; m++)
	{
		CK_FUNCTION_LIST* module = g_ptr_array_index(modules, m);
		g_autoptr(GPtrArray) slots = slots_with_token(module);

		for (guint s = 0; s < slots->len; s++)
		{
			CK_SLOT_ID slot = (CK_SLOT_ID) GPOINTER_TO_SIZE(g_ptr_array_index(slots, s));
			g_autoptr(CertificateToken) present = token_from_slot(tokens, module, slot);

			if (present == NULL || !certificate_token_same_presence(present, token))
				continue;

			/* Three booleans, written from the login worker thread and read on
			 * the main thread after that worker has completed, which is a
			 * happens-before the GTask completion gives for free. Nothing else
			 * about the token is touched: this is the PIN state, not a
			 * re-discovery. */
			token->pin_count_low = present->pin_count_low;
			token->pin_final_try = present->pin_final_try;
			token->pin_locked = present->pin_locked;

			g_mutex_unlock(&tokens->lock);
			return;
		}
	}

	g_mutex_unlock(&tokens->lock);
}

void certificate_tokens_capabilities(CertificateTokens* tokens, GStrv* mechanisms_out,
                                     gboolean* protected_path_out)
{
	g_autoptr(GStrvBuilder) builder = g_strv_builder_new();
	g_autoptr(GPtrArray) modules = NULL;
	gboolean rsa_pkcs = FALSE;
	gboolean rsa_pss = FALSE;
	gboolean rsa_oaep = FALSE;
	gboolean ecdsa = FALSE;
	gboolean protected_path = FALSE;
	gboolean any_token = FALSE;

	g_mutex_lock(&tokens->lock);
	modules = module_list(tokens);

	for (guint m = 0; m < modules->len; m++)
	{
		CK_FUNCTION_LIST* module = g_ptr_array_index(modules, m);
		g_autoptr(GPtrArray) slots = slots_with_token(module);

		for (guint s = 0; s < slots->len; s++)
		{
			CK_SLOT_ID slot = (CK_SLOT_ID) GPOINTER_TO_SIZE(g_ptr_array_index(slots, s));
			g_autoptr(CertificateToken) token = token_from_slot(tokens, module, slot);

			if (token == NULL || token_skip_reason(tokens, token) != NULL)
				continue;

			any_token = TRUE;
			protected_path = protected_path || token->protected_authentication_path;
			rsa_pkcs = rsa_pkcs || certificate_pkcs11_has_mechanism(module, slot, CKM_RSA_PKCS);
			rsa_pss = rsa_pss || certificate_pkcs11_has_mechanism(module, slot, CKM_RSA_PKCS_PSS);
			rsa_oaep =
			    rsa_oaep || certificate_pkcs11_has_mechanism(module, slot, CKM_RSA_PKCS_OAEP);
			ecdsa = ecdsa || certificate_pkcs11_has_mechanism(module, slot, CKM_ECDSA);
		}
	}
	g_mutex_unlock(&tokens->lock);

	/* WITH NO TOKEN PRESENT, report what this backend can drive rather than the
	 * empty set: GetCapabilities is a question about the backend, asked so that
	 * an application can adapt WITHOUT provoking a dialog, and answering "no
	 * mechanisms" because the card is in the user's pocket would make every
	 * caller conclude the feature does not exist. AcquireCredential is where
	 * the absence of a card is reported, and it reports it honestly. */
	if (!any_token)
	{
		rsa_pkcs = TRUE;
		rsa_pss = TRUE;
		rsa_oaep = TRUE;
		ecdsa = TRUE;
	}

	if (rsa_pkcs)
		g_strv_builder_add(builder, "RSA_PKCS1_V1_5");
	if (rsa_pss)
		g_strv_builder_add(builder, "RSA_PSS");
	if (rsa_oaep)
		g_strv_builder_add(builder, "RSA_OAEP");
	if (ecdsa)
		g_strv_builder_add(builder, "ECDSA");

	if (mechanisms_out != NULL)
		*mechanisms_out = g_strv_builder_end(builder);
	if (protected_path_out != NULL)
		*protected_path_out = protected_path;
}

/* -------------------------------------------------------- presence watching */

typedef struct
{
	CertificateTokens* tokens;
	CertificateToken* token;
	gboolean added;
} WatchEvent;

static gboolean watch_dispatch(gpointer user_data)
{
	WatchEvent* event = user_data;

	if (event->tokens->watch_event != NULL)
		event->tokens->watch_event(event->token, event->added, event->tokens->watch_data);

	return G_SOURCE_REMOVE;
}

static void watch_event_free(gpointer user_data)
{
	WatchEvent* event = user_data;

	certificate_token_unref(event->token);
	g_free(event);
}

static void watch_emit(CertificateTokens* tokens, CertificateToken* token, gboolean added)
{
	WatchEvent* event = g_new0(WatchEvent, 1);
	GSource* source = g_idle_source_new();

	event->tokens = tokens;
	event->token = certificate_token_ref(token);
	event->added = added;

	g_source_set_callback(source, watch_dispatch, event, watch_event_free);
	g_source_attach(source, tokens->watch_context);
	g_source_unref(source);
}

static gboolean list_contains_token(GPtrArray* list, const CertificateToken* token)
{
	for (guint i = 0; i < list->len; i++)
	{
		if (certificate_token_same_presence(g_ptr_array_index(list, i), token))
			return TRUE;
	}

	return FALSE;
}

static gpointer watch_thread(gpointer user_data)
{
	CertificateTokens* tokens = user_data;
	guint stable = 0;

	tokens->watch_known = certificate_tokens_list(tokens, NULL);

	while (!g_atomic_int_get(&tokens->watch_stop))
	{
		g_autoptr(GPtrArray) now = NULL;
		gboolean changed = FALSE;

		g_usleep(CERTIFICATE_WATCH_INTERVAL_MS * 1000);
		if (g_atomic_int_get(&tokens->watch_stop))
			break;

		now = certificate_tokens_list(tokens, NULL);

		if (now->len != tokens->watch_known->len)
			changed = TRUE;
		else
		{
			for (guint i = 0; i < now->len && !changed; i++)
			{
				if (!list_contains_token(tokens->watch_known, g_ptr_array_index(now, i)))
					changed = TRUE;
			}
		}

		if (!changed)
		{
			stable = 0;
			continue;
		}

		/* Debounce: a reader that reports insert and remove repeatedly must not
		 * produce a signal storm, so a change has to survive consecutive polls
		 * before anything is emitted. */
		stable++;
		if (stable < CERTIFICATE_WATCH_DEBOUNCE)
			continue;
		stable = 0;

		for (guint i = 0; i < tokens->watch_known->len; i++)
		{
			CertificateToken* old = g_ptr_array_index(tokens->watch_known, i);

			if (!list_contains_token(now, old))
				watch_emit(tokens, old, FALSE);
		}

		for (guint i = 0; i < now->len; i++)
		{
			CertificateToken* fresh = g_ptr_array_index(now, i);

			if (!list_contains_token(tokens->watch_known, fresh))
				watch_emit(tokens, fresh, TRUE);
		}

		g_clear_pointer(&tokens->watch_known, g_ptr_array_unref);
		tokens->watch_known = g_ptr_array_ref(now);
	}

	return NULL;
}

void certificate_tokens_watch(CertificateTokens* tokens, CertificateTokenEvent event,
                              gpointer user_data)
{
	if (tokens->watch_thread != NULL)
		return;

	tokens->watch_event = event;
	tokens->watch_data = user_data;
	tokens->watch_context = g_main_context_ref_thread_default();
	g_atomic_int_set(&tokens->watch_stop, FALSE);
	tokens->watch_thread = g_thread_new("certificate-tokens", watch_thread, tokens);
}

void certificate_tokens_stop_watch(CertificateTokens* tokens)
{
	if (tokens->watch_thread == NULL)
		return;

	g_atomic_int_set(&tokens->watch_stop, TRUE);
	g_thread_join(tokens->watch_thread);
	tokens->watch_thread = NULL;
	g_clear_pointer(&tokens->watch_context, g_main_context_unref);
}
