/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef CERTIFICATE_TOKENS_DISCOVERY_H
#define CERTIFICATE_TOKENS_DISCOVERY_H

#include <gio/gio.h>
#include <glib.h>

#include "pkcs11-util.h"

/** Token identity and discovery constraints are documented in docs/IMPL-INTERFACE.md. */

#define CERTIFICATE_P11_KIT_TRUST_MODEL "p11-kit-trust"

/** Serials are identity metadata: never send them on the wire or log them unredacted. */
typedef struct
{
	gatomicrefcount ref_count;

	char* label;
	char* manufacturer;
	char* model;
	char* serial;
	char* reader_name;
	char* module_name;

	gboolean protected_authentication_path; /**< Protected authentication requires a reader or token PIN prompt without a backend PIN field. */
	gboolean login_required;
	/** Hardware status is a CK_SLOT_INFO flag claimed by the module; it is not a verified security boundary. */
	gboolean hardware;
	gboolean module_named_explicitly;
	/** Static skip reason; only certificate_tokens_list_all() returns skipped tokens. */
	const char* skip_reason;
	gboolean pin_count_low;
	gboolean pin_final_try;
	gboolean pin_locked;

	/* Slots are locations; reopen only after resolving the stable identity fields. */
	CK_FUNCTION_LIST* module;
	CK_SLOT_ID slot;
} CertificateToken;

CertificateToken* certificate_token_ref(CertificateToken* token);
void certificate_token_unref(CertificateToken* token);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(CertificateToken, certificate_token_unref)

gboolean certificate_token_same(const CertificateToken* a, const CertificateToken* b);

/** Bookkeeping identity only; never log or send on the wire. */
char* certificate_token_identity(const CertificateToken* token);

/** Serial-less presence matching uses location and names; it must never rebind grants. */
gboolean certificate_token_same_presence(const CertificateToken* a, const CertificateToken* b);


typedef struct
{
	gatomicrefcount ref_count;

	CertificateToken* token;
	GByteArray* der;
	GByteArray* cka_id;

	char* certificate_id;  /**< Hex SHA-256 of @der. */
	char* subject_display; /**< Chooser only; never logged. */
	char* issuer_display;  /**< Chooser only; never logged. */
	char* subject_dn;      /**< Full RFC 4514 DN for details. */
	GByteArray* issuer_der; /**< DER issuer DN for certificate_filter.issuers. */

	gint64 not_before;
	gint64 not_after;

	char** eku_oids; /**< NULL for absent EKU; an empty array means no allowed purposes. */
	char** key_usage;
	char* piv_slot; /**< Best effort; NULL if unknown. */
	char* key_type;
	guint key_size;
	char* key_curve;

	gboolean can_sign;
	gboolean can_decrypt;
	char** supported_mechanisms; /**< Portal mechanism names supported by both key and token. */
} CertificateCandidate;

CertificateCandidate* certificate_candidate_ref(CertificateCandidate* candidate);
void certificate_candidate_unref(CertificateCandidate* candidate);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(CertificateCandidate, certificate_candidate_unref)

/** Match a certificate and key on the same stable token identity. */
gboolean certificate_candidate_same(const CertificateCandidate* a, const CertificateCandidate* b);

/** Parses certificate-derived fields only; the caller fills token-derived fields. */
CertificateCandidate* certificate_candidate_new_from_der(const guint8* der, gsize length,
                                                         GError** error);

gboolean certificate_candidate_is_expired(const CertificateCandidate* candidate, gint64 now);
gboolean certificate_candidate_is_not_yet_valid(const CertificateCandidate* candidate, gint64 now);

typedef struct CertificateTokens CertificateTokens;

/** Explicit paths replace configured loading; an empty list loads no modules. */
CertificateTokens* certificate_tokens_new(const char* const* module_paths, GError** error);

/** Reject the portal client module even when explicitly selected to prevent recursive backend calls. */
gboolean certificate_module_is_portal_module(const char* name, const char* filename);
void certificate_tokens_free(CertificateTokens* tokens);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(CertificateTokens, certificate_tokens_free)

/** Blocking enumeration returns CertificateCandidate* elements; use a worker or the async form. */
GPtrArray* certificate_tokens_enumerate(CertificateTokens* tokens, GCancellable* cancellable,
                                        GError** error);

void certificate_tokens_enumerate_async(CertificateTokens* tokens, GCancellable* cancellable,
                                        GAsyncReadyCallback callback, gpointer user_data);
GPtrArray* certificate_tokens_enumerate_finish(CertificateTokens* tokens, GAsyncResult* result,
                                               gboolean* tokens_present, GError** error);

/** The test gate runs on a worker after enumeration, without locks held. */
typedef void (*CertificateEnumerateGate)(gpointer user_data);
void certificate_tokens_set_enumerate_gate(CertificateEnumerateGate gate, gpointer user_data);

GPtrArray* certificate_tokens_list(CertificateTokens* tokens, GError** error);

GPtrArray* certificate_tokens_list_all(CertificateTokens* tokens, GError** error);

/** Software tokens require an explicit override or --module; hardware flags are module claims. */
void certificate_tokens_set_allow_software(CertificateTokens* tokens, gboolean allow);

/** Re-resolve token identity before opening; a replacement card in the same slot counts as removal. */
gboolean certificate_tokens_open_session(CertificateTokens* tokens, const CertificateToken* token,
                                         CK_FUNCTION_LIST** module_out,
                                         CK_SESSION_HANDLE* session_out, GError** error);

/** Presence events stay internal; the wire interface exposes only grant invalidation. */
typedef void (*CertificateTokenEvent)(CertificateToken* token, gboolean added, gpointer user_data);

/** Debounced callbacks run on the caller's thread-default main context. */
void certificate_tokens_watch(CertificateTokens* tokens, CertificateTokenEvent event,
                              gpointer user_data);
void certificate_tokens_stop_watch(CertificateTokens* tokens);
/* After stop, detach the receiver before destroying it. Coordinator only. */
void certificate_tokens_clear_watch(CertificateTokens* tokens);

/** Watch context only: deliver the finite FIFO prefix queued before this call's
 * lock acquisition. Acceptance calls this before granting, independently of
 * source priorities. Polling/debounce precedes enqueue and is not covered. */
void certificate_tokens_dispatch_pending(CertificateTokens* tokens);

/** Main-context test hook delivers a presence event through the active watch callback. */
void certificate_tokens_emit_event(CertificateTokens* tokens, CertificateToken* token,
                                   gboolean added);

/** Refresh PIN flags after each refused login because that attempt may set FINAL_TRY. */
void certificate_tokens_refresh_flags(CertificateTokens* tokens, CertificateToken* token);

/** Backend support only; never inspect inserted tokens or reader flags. */
void certificate_tokens_capabilities(CertificateTokens* tokens, GStrv* mechanisms_out,
                                     gboolean* protected_path_out);

#endif
