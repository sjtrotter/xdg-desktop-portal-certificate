/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */
#ifndef CERTIFICATE_TOKENS_DISCOVERY_H
#define CERTIFICATE_TOKENS_DISCOVERY_H

#include <gio/gio.h>
#include <glib.h>

#include "pkcs11-util.h"

/** @file
 *  Finding tokens and the certificates on them.
 *
 *  DEVICE ACCESS IS THE BACKEND'S. The frontend never loads a PKCS#11 module,
 *  never talks to p11-kit and never learns a card serial: it could not do any
 *  of it usefully without becoming the thing the split exists to separate.
 *
 *  Enumerates slots and tokens through p11-kit's configured managed modules,
 *  on a worker thread and under a GCancellable, and watches for insertion and
 *  removal.
 *
 *  THE HARDWARE EDGE CASES ARE THE SPECIFICATION. They were found by running
 *  Remmina's RDP plugin against real cards (GPL-2.0-or-later, not copied here),
 *  and they survive the change from a p11tool subprocess to the p11-kit API
 *  unaltered, because they are a list of things CARDS do:
 *
 *   - p11-kit's own trust tokens (model "p11-kit-trust") never hold client
 *     certificates and are skipped without any work;
 *   - a token holding no matching object reports FAILURE with no output; that
 *     is not an error and must not abort discovery;
 *   - a slot that fails to open, or a token that fails to enumerate, takes that
 *     token out of the result and leaves every other token in it;
 *   - loading a certificate can take seconds, and must never block the main
 *     loop;
 *   - discovery must be cancellable at any point, because a wedged middleware
 *     daemon is a normal Tuesday.
 *
 *  TOKENS ARE IDENTIFIED BY EVERY STABLE ATTRIBUTE AVAILABLE -- manufacturer,
 *  model, serial, label -- and NEVER by slot number, and never by label alone.
 *  A card reinserted into the same slot with the same label is a DIFFERENT
 *  token until proven otherwise; see docs/SPIKES.md S4.
 */

#define CERTIFICATE_P11_KIT_TRUST_MODEL "p11-kit-trust"

/** Token identity. The display fields go in the chooser and in
 *  token_display; the identity fields decide whether two observations are the
 *  same token. The serial is NEVER logged unredacted and is NOT put on the
 *  wire; see src/redact.h and docs/IMPL-INTERFACE.md. */
typedef struct
{
	gatomicrefcount ref_count;

	char* label;
	char* manufacturer;
	char* model;
	char* serial;
	char* reader_name;
	char* module_name; /**< the p11-kit module this token was seen through */

	gboolean protected_authentication_path; /**< CKF_PROTECTED_AUTHENTICATION_PATH: the
	                                             token or reader collects the PIN, and
	                                             ui/pin.h must NOT draw a PIN field */
	gboolean login_required;
	gboolean pin_count_low;
	gboolean pin_final_try;
	gboolean pin_locked;

	/* Where it was last seen. Slot ids are NOT identity: they are re-resolved
	 * from the identity fields above every time a session is opened. */
	CK_FUNCTION_LIST* module;
	CK_SLOT_ID slot;
} CertificateToken;

CertificateToken* certificate_token_ref(CertificateToken* token);
void certificate_token_unref(CertificateToken* token);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(CertificateToken, certificate_token_unref)

/** True when the two observations are of the same token. Slot number is not
 *  part of the comparison, and neither is the label on its own. */
gboolean certificate_token_same(const CertificateToken* a, const CertificateToken* b);

/** A stable string identifying the token, for grant bookkeeping only. Never
 *  logged, never put on the wire. */
char* certificate_token_identity(const CertificateToken* token);

/** One candidate certificate, before filtering. */
typedef struct
{
	gatomicrefcount ref_count;

	CertificateToken* token;
	GByteArray* der;
	GByteArray* cka_id;

	char* certificate_id;  /**< stable identifier: the SHA-256 of @der, hex */
	char* subject_display; /**< for the chooser only; never logged */
	char* issuer_display;  /**< for the chooser only; never logged */
	char* subject_dn;      /**< the full RFC 4514 DN, for the details view */
	GByteArray* issuer_der; /**< the DER issuer name, for certificate_filter.issuers */

	gint64 not_before;
	gint64 not_after;

	char** eku_oids; /**< NULL when the certificate has no EKU extension at all */
	char** key_usage;
	char* piv_slot; /**< best effort; NULL when it cannot be determined */
	char* key_type; /**< "RSA" or "EC" */
	guint key_size;
	char* key_curve;

	gboolean can_sign;
	gboolean can_decrypt;
	char** supported_mechanisms; /**< portal mechanism names the KEY and TOKEN support */
} CertificateCandidate;

CertificateCandidate* certificate_candidate_ref(CertificateCandidate* candidate);
void certificate_candidate_unref(CertificateCandidate* candidate);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(CertificateCandidate, certificate_candidate_unref)

/** Build a candidate from a certificate DER alone, with no token behind it.
 *  This is what the unit tests use: every X.509-derived field the purpose and
 *  filter rules read is set from @der, and the token-derived fields are left
 *  for the caller to fill in. Returns NULL when @der is not a certificate. */
CertificateCandidate* certificate_candidate_new_from_der(const guint8* der, gsize length,
                                                         GError** error);

gboolean certificate_candidate_is_expired(const CertificateCandidate* candidate, gint64 now);
gboolean certificate_candidate_is_not_yet_valid(const CertificateCandidate* candidate, gint64 now);

typedef struct CertificateTokens CertificateTokens;

/** Load and initialize the PKCS#11 modules.
 *
 *  @module_paths, when non-NULL and non-empty, is an explicit allow-list of
 *  module paths (--module) and NOTHING ELSE IS LOADED. When it is NULL the
 *  p11-kit configured managed modules are used, minus the ones this backend
 *  has no business in: p11-kit's own trust module holds no client certificates
 *  and gnome-keyring's holds software keys the user did not put on a token. */
CertificateTokens* certificate_tokens_new(const char* const* module_paths, GError** error);
void certificate_tokens_free(CertificateTokens* tokens);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(CertificateTokens, certificate_tokens_free)

/** Enumerate every token with a certificate that has a matching private key.
 *  BLOCKS: call it on a worker thread, or use the async form. Returns a
 *  GPtrArray of CertificateCandidate*. An empty array is a normal answer. */
GPtrArray* certificate_tokens_enumerate(CertificateTokens* tokens, GCancellable* cancellable,
                                        GError** error);

void certificate_tokens_enumerate_async(CertificateTokens* tokens, GCancellable* cancellable,
                                        GAsyncReadyCallback callback, gpointer user_data);
GPtrArray* certificate_tokens_enumerate_finish(CertificateTokens* tokens, GAsyncResult* result,
                                               GError** error);

/** The tokens currently present, without reading any certificate off them.
 *  Used by --list-tokens and by the presence watcher. */
GPtrArray* certificate_tokens_list(CertificateTokens* tokens, GError** error);

/** Re-resolve @token to a slot that currently holds it and open a read-only
 *  session on it. Fails with CERTIFICATE_PKCS11_ERROR_TOKEN_REMOVED when the
 *  token is not present any more -- including when a DIFFERENT card now sits in
 *  the same slot. */
gboolean certificate_tokens_open_session(CertificateTokens* tokens, const CertificateToken* token,
                                         CK_FUNCTION_LIST** module_out,
                                         CK_SESSION_HANDLE* session_out, GError** error);

/** Token presence watching, feeding TokenAdded/TokenRemoved and grant
 *  invalidation.
 *
 *  There is deliberately no ListTokens on the D-Bus interface: enumerating a
 *  user's tokens with no UI discloses which cards, how many readers and whose
 *  issuance to a caller that has not been through a consent dialog. These
 *  signals are justified by a demonstrated need -- reacting to removal mid-flow
 *  -- and enumeration on demand is not, yet. */
typedef void (*CertificateTokenEvent)(CertificateToken* token, gboolean added, gpointer user_data);

/** Start the presence watcher. The callback runs on the thread-default main
 *  context of the caller. Debounced: a reader that reports insert and remove
 *  repeatedly produces one event per settled change, not a signal storm. */
void certificate_tokens_watch(CertificateTokens* tokens, CertificateTokenEvent event,
                              gpointer user_data);
void certificate_tokens_stop_watch(CertificateTokens* tokens);

/** The mechanisms, in the frontend's vocabulary, that at least one present
 *  token supports; and whether any present token has a protected
 *  authentication path. Both feed GetCapabilities. */
void certificate_tokens_capabilities(CertificateTokens* tokens, GStrv* mechanisms_out,
                                     gboolean* protected_path_out);

#endif /* CERTIFICATE_TOKENS_DISCOVERY_H */
