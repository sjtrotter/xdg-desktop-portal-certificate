/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */

#include "filter.h"

#include <string.h>

static gboolean strv_has(char** strv, const char* needle)
{
	if (strv == NULL || needle == NULL)
		return FALSE;

	return g_strv_contains((const char* const*) strv, needle);
}

static gboolean strv_has_ci(char** strv, const char* needle)
{
	if (strv == NULL || needle == NULL)
		return FALSE;

	for (gsize i = 0; strv[i] != NULL; i++)
	{
		if (g_ascii_strcasecmp(strv[i], needle) == 0)
			return TRUE;
	}

	return FALSE;
}

/* A certificate with no extended key usage extension is not restricted by one:
 * X.509 says the key may be used for any purpose. eku_oids is NULL in exactly
 * that case, which is why it is NULL rather than an empty array. */
static gboolean eku_unrestricted(const CertificateCandidate* candidate)
{
	return candidate->eku_oids == NULL;
}

static gboolean eku_allows(const CertificateCandidate* candidate, const char* oid)
{
	if (eku_unrestricted(candidate))
		return TRUE;

	if (strv_has(candidate->eku_oids, CERTIFICATE_EKU_ANY))
		return TRUE;

	return strv_has(candidate->eku_oids, oid);
}

/* No key usage extension means the key is not restricted by one. */
static gboolean key_usage_allows_signing(const CertificateCandidate* candidate)
{
	if (candidate->key_usage == NULL)
		return TRUE;

	return strv_has(candidate->key_usage, "digital_signature") ||
	       strv_has(candidate->key_usage, "content_commitment");
}

gboolean certificate_purpose_matches(const CertificateCandidate* candidate,
                                     CertificatePurpose purpose)
{
	/* Whatever the purpose, a certificate whose private key will not sign is
	 * not a candidate for any of them: every purpose here ends in a signature.
	 * The card is the authority on that, not the certificate's key usage. */
	if (!candidate->can_sign)
		return FALSE;

	switch (purpose)
	{
		case CERTIFICATE_PURPOSE_CLIENT_AUTH:
			/* clientAuth, or the Microsoft smart-card logon OID that PIV
			 * authentication certificates carry, or no EKU restriction at all
			 * together with a key usage that permits signing. */
			if (!key_usage_allows_signing(candidate))
				return FALSE;
			if (eku_unrestricted(candidate))
				return TRUE;
			return eku_allows(candidate, CERTIFICATE_EKU_CLIENT_AUTH) ||
			       strv_has(candidate->eku_oids, CERTIFICATE_EKU_SMARTCARD_LOGON);

		case CERTIFICATE_PURPOSE_SIGNING:
			if (!key_usage_allows_signing(candidate))
				return FALSE;
			if (eku_unrestricted(candidate))
				return TRUE;
			/* A certificate marked ONLY for server authentication is not a
			 * signing credential the user should be offered here. */
			return strv_has(candidate->eku_oids, CERTIFICATE_EKU_ANY) ||
			       strv_has(candidate->eku_oids, CERTIFICATE_EKU_CODE_SIGNING) ||
			       strv_has(candidate->eku_oids, CERTIFICATE_EKU_EMAIL_PROTECTION) ||
			       strv_has(candidate->eku_oids, CERTIFICATE_EKU_CLIENT_AUTH) ||
			       strv_has(candidate->eku_oids, CERTIFICATE_EKU_SMARTCARD_LOGON);

		case CERTIFICATE_PURPOSE_EMAIL:
			/* Email is the one purpose with a specific EKU, and a certificate
			 * with no EKU at all does qualify -- but one restricted to
			 * something else does not. */
			if (!key_usage_allows_signing(candidate))
				return FALSE;
			return eku_allows(candidate, CERTIFICATE_EKU_EMAIL_PROTECTION);

		case CERTIFICATE_PURPOSE_SSH:
			/* SSH does not look at X.509 extensions at all: it uses the raw
			 * key. Any RSA or EC key that will sign qualifies, which is why
			 * this is its own purpose rather than "signing with extra steps". */
			return g_strcmp0(candidate->key_type, "RSA") == 0 ||
			       g_strcmp0(candidate->key_type, "EC") == 0;

		default:
			return FALSE;
	}
}

static gboolean issuer_matches(const CertificateCandidate* candidate, GPtrArray* issuers)
{
	if (issuers == NULL || issuers->len == 0)
		return TRUE;

	if (candidate->issuer_der == NULL)
		return FALSE;

	for (guint i = 0; i < issuers->len; i++)
	{
		GBytes* wanted = g_ptr_array_index(issuers, i);
		gsize size = 0;
		const guint8* data = g_bytes_get_data(wanted, &size);

		if (size == candidate->issuer_der->len &&
		    memcmp(data, candidate->issuer_der->data, size) == 0)
			return TRUE;
	}

	return FALSE;
}

/* "key types and signature schemes the CALLER can use". A value matches when it
 * names the key type ("RSA", "EC"), or one of the mechanisms this candidate
 * actually supports ("ECDSA", "RSA_PSS", ...). Anything else is treated as a
 * scheme name whose prefix says which key it needs, which is how TLS-flavoured
 * names like "ecdsa_secp256r1_sha256" and "rsa_pss_rsae_sha256" arrive. */
static gboolean key_algorithm_matches(const CertificateCandidate* candidate, char** algorithms)
{
	if (algorithms == NULL || algorithms[0] == NULL)
		return TRUE;

	for (gsize i = 0; algorithms[i] != NULL; i++)
	{
		const char* wanted = algorithms[i];

		if (g_ascii_strcasecmp(wanted, candidate->key_type) == 0)
			return TRUE;

		if (strv_has_ci(candidate->supported_mechanisms, wanted))
			return TRUE;

		if (g_ascii_strncasecmp(wanted, "rsa", 3) == 0 &&
		    g_strcmp0(candidate->key_type, "RSA") == 0)
			return TRUE;

		if ((g_ascii_strncasecmp(wanted, "ecdsa", 5) == 0 ||
		     g_ascii_strncasecmp(wanted, "ec", 2) == 0) &&
		    g_strcmp0(candidate->key_type, "EC") == 0)
			return TRUE;
	}

	return FALSE;
}

gboolean certificate_filter_matches(const CertificateCandidate* candidate,
                                    const CertificateFilter* filter)
{
	if (!certificate_purpose_matches(candidate, filter->purpose))
		return FALSE;

	if (!issuer_matches(candidate, filter->issuers))
		return FALSE;

	if (filter->key_usage != NULL)
	{
		for (gsize i = 0; filter->key_usage[i] != NULL; i++)
		{
			if (!strv_has_ci(candidate->key_usage, filter->key_usage[i]))
				return FALSE;
		}
	}

	if (filter->eku_oids != NULL)
	{
		for (gsize i = 0; filter->eku_oids[i] != NULL; i++)
		{
			if (!eku_allows(candidate, filter->eku_oids[i]))
				return FALSE;
		}
	}

	if (!key_algorithm_matches(candidate, filter->key_algorithms))
		return FALSE;

	if (filter->token_label != NULL && *filter->token_label != '\0')
	{
		if (candidate->token == NULL ||
		    g_strcmp0(candidate->token->label, filter->token_label) != 0)
			return FALSE;
	}

	if (filter->piv_slot != NULL && *filter->piv_slot != '\0')
	{
		/* A candidate whose PIV slot could not be determined is NOT a match for
		 * a request that named one. Guessing here would offer the wrong key. */
		if (g_strcmp0(candidate->piv_slot, filter->piv_slot) != 0)
			return FALSE;
	}

	return TRUE;
}

GPtrArray* certificate_filter_apply(GPtrArray* candidates, const CertificateFilter* filter)
{
	GPtrArray* usable =
	    g_ptr_array_new_with_free_func((GDestroyNotify) certificate_candidate_unref);
	GPtrArray* unusable =
	    g_ptr_array_new_with_free_func((GDestroyNotify) certificate_candidate_unref);
	gint64 now = g_get_real_time() / G_USEC_PER_SEC;

	for (guint i = 0; i < candidates->len; i++)
	{
		CertificateCandidate* candidate = g_ptr_array_index(candidates, i);

		if (!certificate_filter_matches(candidate, filter))
			continue;

		/* RULE 1. Expired and not-yet-valid certificates are OFFERED and
		 * MARKED, never hidden -- but they sort below the ones that work, so
		 * that a working credential is never buried under a broken one. */
		if (certificate_candidate_is_expired(candidate, now) ||
		    certificate_candidate_is_not_yet_valid(candidate, now))
			g_ptr_array_add(unusable, certificate_candidate_ref(candidate));
		else
			g_ptr_array_add(usable, certificate_candidate_ref(candidate));
	}

	for (guint i = 0; i < unusable->len; i++)
		g_ptr_array_add(usable, certificate_candidate_ref(g_ptr_array_index(unusable, i)));

	g_ptr_array_unref(unusable);
	return usable;
}

static char** strv_from_variant(GVariant* dict, const char* key, GError** error)
{
	g_autoptr(GVariant) value = g_variant_lookup_value(dict, key, NULL);

	if (value == NULL)
		return NULL;

	if (!g_variant_is_of_type(value, G_VARIANT_TYPE_STRING_ARRAY))
	{
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		            "certificate_filter.%s must be an array of strings", key);
		return NULL;
	}

	return g_variant_dup_strv(value, NULL);
}

gboolean certificate_filter_parse(GVariant* options, CertificatePurpose purpose,
                                  CertificateFilter* out, GError** error)
{
	g_autoptr(GVariant) filter = NULL;
	g_autoptr(GVariant) issuers = NULL;
	const char* text = NULL;
	g_autoptr(GError) local_error = NULL;

	memset(out, 0, sizeof(*out));
	out->purpose = purpose;

	if (options == NULL)
		return TRUE;

	filter = g_variant_lookup_value(options, "certificate_filter", NULL);
	if (filter == NULL)
		return TRUE;

	/* PRESENT WITH THE WRONG TYPE IS NOT ABSENT. It used to be: a mistyped
	 * certificate_filter was silently dropped, and the chooser then offered
	 * certificates the caller had said it could not use. */
	if (!g_variant_is_of_type(filter, G_VARIANT_TYPE_VARDICT))
	{
		g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		                    "certificate_filter must be a vardict");
		return FALSE;
	}

	{
		static const char* const known[] = { "issuers",        "key_usage", "eku",
			                                 "key_algorithms", "token_label", "piv_slot",
			                                 NULL };
		GVariantIter iter;
		const char* key = NULL;

		/* A key nobody understood may have been the one that said "less". */
		g_variant_iter_init(&iter, filter);
		while (g_variant_iter_next(&iter, "{&sv}", &key, NULL))
		{
			if (g_strv_contains(known, key))
				continue;

			g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			            "Unknown certificate_filter key '%s'", key);
			return FALSE;
		}
	}

	/* A filter is REJECTED rather than half-applied. Ignoring a key that was
	 * not understood would offer credentials the caller said it could not use,
	 * and the caller would then fail at the handshake with no way to know why. */
	issuers = g_variant_lookup_value(filter, "issuers", NULL);
	if (issuers != NULL)
	{
		GVariantIter iter;
		GVariant* item = NULL;

		if (!g_variant_is_of_type(issuers, G_VARIANT_TYPE("aay")))
		{
			g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			                    "certificate_filter.issuers must be an array of byte arrays");
			return FALSE;
		}

		out->issuers = g_ptr_array_new_with_free_func((GDestroyNotify) g_bytes_unref);
		g_variant_iter_init(&iter, issuers);
		while ((item = g_variant_iter_next_value(&iter)) != NULL)
		{
			gsize size = 0;
			gconstpointer data = g_variant_get_fixed_array(item, &size, 1);

			g_ptr_array_add(out->issuers, g_bytes_new(data, size));
			g_variant_unref(item);
		}
	}

	out->key_usage = strv_from_variant(filter, "key_usage", &local_error);
	if (local_error != NULL)
		goto invalid;
	out->eku_oids = strv_from_variant(filter, "eku", &local_error);
	if (local_error != NULL)
		goto invalid;
	out->key_algorithms = strv_from_variant(filter, "key_algorithms", &local_error);
	if (local_error != NULL)
		goto invalid;

	if (g_variant_lookup(filter, "token_label", "&s", &text))
	{
		out->token_label = g_strdup(text);
	}
	else
	{
		g_autoptr(GVariant) mistyped = g_variant_lookup_value(filter, "token_label", NULL);

		if (mistyped != NULL)
		{
			g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			                    "certificate_filter.token_label must be a string");
			certificate_filter_clear(out);
			return FALSE;
		}
	}

	if (g_variant_lookup(filter, "piv_slot", "&s", &text))
	{
		static const char* const slots[] = { "authentication", "signature", "key_management",
			                                 "card_authentication", NULL };

		if (!g_strv_contains(slots, text))
		{
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			            "certificate_filter.piv_slot '%s' is not a PIV slot", text);
			certificate_filter_clear(out);
			return FALSE;
		}

		out->piv_slot = g_strdup(text);
	}
	else
	{
		g_autoptr(GVariant) mistyped = g_variant_lookup_value(filter, "piv_slot", NULL);

		if (mistyped != NULL)
		{
			g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			                    "certificate_filter.piv_slot must be a string");
			certificate_filter_clear(out);
			return FALSE;
		}
	}

	return TRUE;

invalid:
	g_propagate_error(error, g_steal_pointer(&local_error));
	certificate_filter_clear(out);
	return FALSE;
}

void certificate_filter_clear(CertificateFilter* filter)
{
	if (filter == NULL)
		return;

	g_clear_pointer(&filter->issuers, g_ptr_array_unref);
	g_clear_pointer(&filter->key_usage, g_strfreev);
	g_clear_pointer(&filter->eku_oids, g_strfreev);
	g_clear_pointer(&filter->key_algorithms, g_strfreev);
	g_clear_pointer(&filter->token_label, g_free);
	g_clear_pointer(&filter->piv_slot, g_free);
}
