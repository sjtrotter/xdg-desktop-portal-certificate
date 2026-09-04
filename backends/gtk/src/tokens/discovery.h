/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SMARTCARD_TOKENS_DISCOVERY_H
#define SMARTCARD_TOKENS_DISCOVERY_H

#include <glib.h>

/** @file
 *  Finding tokens and the certificates on them.
 *
 *  DEVICE ACCESS IS THE BACKEND'S. The frontend never loads a PKCS#11 module, never
 *  talks to p11-kit and never learns a card serial: it could not do any of it usefully
 *  without becoming the thing the split exists to separate.
 *
 *  Enumerates slots and tokens through p11-kit's configured managed modules,
 *  asynchronously and under a GCancellable, and watches for insertion and removal.
 *
 *  THE HARDWARE EDGE CASES ARE THE SPECIFICATION. They were found by running Remmina's
 *  RDP plugin against real cards (GPL-2.0-or-later, not copied here), and they survive
 *  the change from a p11tool subprocess to the p11-kit API unaltered, because they are a
 *  list of things CARDS do:
 *
 *   - p11-kit's own trust tokens (model "p11-kit-trust") never hold client certificates
 *     and are skipped without any work;
 *   - a token holding no matching object reports FAILURE with no output; that is not an
 *     error and must not abort discovery;
 *   - a failure WITH output, a killed process, an output-limit breach, or a
 *     token-listing failure all remain fatal;
 *   - loading a certificate can take seconds, and must never block the main loop;
 *   - discovery must be cancellable at any point, because a wedged middleware daemon is
 *     a normal Tuesday.
 *
 *  TOKENS ARE IDENTIFIED BY EVERY STABLE ATTRIBUTE AVAILABLE -- manufacturer, model,
 *  serial, label -- and NEVER by slot number, and never by label alone. A card
 *  reinserted into the same slot with the same label is a DIFFERENT token until proven
 *  otherwise; see docs/SPIKES.md S4, which exists to prove exactly this.
 *
 *  Sketch only; nothing here is implemented.
 */

#define SMARTCARD_P11_KIT_TRUST_MODEL "p11-kit-trust"

/** Token identity. The display fields go in the chooser and in token_display; the
 *  identity fields decide whether two observations are the same token. Neither set is
 *  ever logged: shared/redact.h permits token PRESENCE, not token identity. */
typedef struct
{
	char* label;
	char* manufacturer;
	char* model;
	char* serial;
	char* reader_name;
	gboolean protected_authentication_path; /**< CKF_PROTECTED_AUTHENTICATION_PATH: the
	                                             token or reader collects the PIN, and
	                                             ui/pin.h must NOT draw a PIN field */
	gboolean login_required;
	gint retries_remaining; /**< -1 when the token does not reliably report it. NEVER
	                             invent a value: a wrong count is worse than none. */
} SmartcardToken;

/** One candidate certificate, before filtering. */
typedef struct
{
	SmartcardToken* token;
	GByteArray* der;
	char* subject_display; /**< for the chooser only; never logged */
	char* issuer_display;  /**< for the chooser only; never logged */
	gint64 not_before;
	gint64 not_after;
	char** eku_oids;
	char** key_usage;
	char* piv_slot;  /**< "authentication", "signature", "key_management", "card_authentication" */
	char* key_type;  /**< "RSA" or "EC" */
	guint key_size;
	char* key_curve;
} SmartcardCandidate;

typedef struct SmartcardDiscovery SmartcardDiscovery;

typedef void (*SmartcardDiscoveryDone)(GPtrArray* candidates, const GError* error,
                                       gpointer user_data);

/** Start discovery. Never blocks; @done runs on the main context. Cancelling the
 *  transaction cancels this, and a cancelled discovery reports no error -- a user who
 *  closed the window does not need a dialog about it. */
SmartcardDiscovery* smartcard_discovery_start(GCancellable* cancellable,
                                              SmartcardDiscoveryDone done, gpointer user_data);

void smartcard_discovery_cancel(SmartcardDiscovery* discovery);

/** Token presence watching, feeding TokenAdded/TokenRemoved and grant invalidation.
 *  A reader that reports insert/remove repeatedly must not produce a signal storm; the
 *  watcher debounces, and docs/SPIKES.md S4 sets the threshold from real hardware.
 *
 *  There is deliberately no ListTokens on the D-Bus interface: enumerating a user's
 *  tokens with no UI discloses which cards, how many readers and whose issuance to a
 *  caller that has not been through a consent dialog. These signals are justified by a
 *  demonstrated need -- reacting to removal mid-flow -- and enumeration on demand is
 *  not, yet. */
typedef void (*SmartcardTokenEvent)(const SmartcardToken* token, gboolean added,
                                    gpointer user_data);

SmartcardDiscovery* smartcard_discovery_watch(SmartcardTokenEvent event, gpointer user_data);

void smartcard_token_free(SmartcardToken* token);
void smartcard_candidate_free(SmartcardCandidate* candidate);

#endif /* SMARTCARD_TOKENS_DISCOVERY_H */
