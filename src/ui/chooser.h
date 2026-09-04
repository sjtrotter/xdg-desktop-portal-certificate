/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SMARTCARD_UI_CHOOSER_H
#define SMARTCARD_UI_CHOOSER_H

#include <glib.h>

#include "../tokens/discovery.h"

/** @file
 *  The trusted chooser. THIS WINDOW IS THE CONSENT DECISION.
 *
 *  Not the PIN prompt. The PIN proves the user was present and knew the PIN; it does not
 *  tell them which application asked, for what, or how long the answer lasts. A design
 *  where the PIN prompt is the only user-visible moment has taught the user to type
 *  their PIN whenever asked, which is precisely what an attacker needs.
 *
 *  WHAT THE WINDOW MUST SHOW, in text the caller cannot influence:
 *
 *   1. verified application NAME and ID;
 *   2. SANDBOXED or UNSANDBOXED, with an explicit warning for unverified callers;
 *   3. the purpose IN THIS SERVICE'S OWN WORDS, never the caller's;
 *   4. the operation class being granted: authenticate, sign, or decrypt;
 *   5. the certificate: subject identity, issuer, and a fingerprint or short stable
 *      identifier behind a details view;
 *   6. the token and reader name;
 *   7. the grant duration, or "this operation only";
 *   8. WHETHER FURTHER OPERATIONS MAY HAPPEN WITHOUT ANOTHER PROMPT -- stated plainly,
 *      because this is the part users get wrong;
 *   9. the caller's reason and context strings, visibly separated and LABELLED AS
 *      APPLICATION-PROVIDED TEXT.
 *
 *  NOTHING CALLER-SUPPLIED MAY OCCUPY THE TRUSTED IDENTITY POSITION. Not reason, not
 *  context, not a title, not the token label, not the certificate subject. A caller that
 *  sends reason "Microsoft Login" must not get a window that reads as Microsoft's.
 *
 *  For client authentication the destination host matters and this service CANNOT verify
 *  it: it sees a D-Bus peer, not a TLS connection. context carries it and is displayed as
 *  the REQUESTED destination. Selection memory is keyed only on trusted fields.
 *
 *  ACCESSIBILITY IS AN ACCEPTANCE CRITERION, NOT POLISH. A security dialog a
 *  screen-reader user cannot navigate is a dialog that user cannot give informed consent
 *  through. AT-SPI exposure for every control, complete keyboard-only operation,
 *  meaningful focus order, announcement of the verified caller and sandbox status and
 *  purpose and operation class, scalable text, high contrast, reduced animation, no
 *  information carried by colour alone (including "expired"), accessible error and
 *  cancellation states, and focus restored to the calling application afterwards.
 *
 *  Behind a vtable so a Qt/KDE implementation is a second implementation rather than a
 *  fork. There is no KDE equivalent of GNOME's gcr prompter to defer to; see
 *  docs/decisions/0002-service-owned-pin-prompt.md.
 *
 *  Sketch only; nothing here is implemented.
 */

/** How much this service actually knows about who is asking. The chooser DISPLAYS which
 *  level it got; see docs/SECURITY.md. */
typedef enum
{
	SMARTCARD_IDENTITY_VERIFIED_SANDBOXED, /**< Flatpak/Snap identity via the containment
	                                            framework's mediation: authenticated metadata */
	SMARTCARD_IDENTITY_DERIVED_HOST,       /**< cgroup-derived desktop label: a useful label,
	                                            NOT a security principal. Warn. */
	SMARTCARD_IDENTITY_UNKNOWN             /**< nothing trustworthy: "an unidentified
	                                            application", strongest warning, first-use
	                                            confirmation, no selection memory */
} SmartcardIdentityLevel;

typedef struct
{
	SmartcardIdentityLevel level;
	char* app_name; /**< as THIS SERVICE established it. Never caller-supplied text. */
	char* app_id;
	char* unique_bus_name;
	gboolean sandboxed;
} SmartcardCallerIdentity;

typedef struct
{
	const SmartcardCallerIdentity* caller;
	SmartcardPurpose purpose;
	gboolean may_sign;
	gboolean may_decrypt;
	guint32 lifetime_seconds; /**< 0 means "this operation only" */
	gboolean may_prompt_later;
	const char* reason;  /**< UNTRUSTED. Displayed labelled, subordinate. Never logged. */
	const char* context; /**< UNTRUSTED. Displayed as the REQUESTED destination. */
	gboolean offer_selection_memory; /**< preselection only, and never for level UNKNOWN */
} SmartcardChooserRequest;

typedef struct
{
	SmartcardCandidate* chosen; /**< NULL if the user cancelled */
	gboolean remember_selection;
} SmartcardChooserResult;

typedef void (*SmartcardChooserDone)(const SmartcardChooserResult* result, gpointer user_data);

/** Show the chooser. @parent_window uses the portal window-identifier convention
 *  ("wayland:<handle>" from xdg_foreign, "x11:<xid>", or empty). AN INVALID OR EXPIRED
 *  PARENT MUST NOT FAIL THE REQUEST: degrade to an unparented, service-controlled
 *  window. @activation_token authorises focus; a background caller without one does not
 *  steal it. */
void smartcard_chooser_show(const char* parent_window, const char* activation_token,
                            GPtrArray* candidates, const SmartcardChooserRequest* request,
                            GCancellable* cancellable, SmartcardChooserDone done,
                            gpointer user_data);

#endif /* SMARTCARD_UI_CHOOSER_H */
