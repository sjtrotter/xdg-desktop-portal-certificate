/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SMARTCARD_UI_CHOOSER_H
#define SMARTCARD_UI_CHOOSER_H

#include <glib.h>

#include "../smartcard.h"
#include "../tokens/discovery.h"

/** @file
 *  The trusted chooser. THIS WINDOW IS THE CONSENT DECISION.
 *
 *  DRAWN BY THE BACKEND, FROM FACTS THE FRONTEND ESTABLISHED. This is the division
 *  upstream makes for every portal that asks a question, and it is the one that makes
 *  the answer trustworthy: the side that knows who is calling is not the side that draws
 *  the window, so the window cannot be talked into naming the wrong application by the
 *  application. app_id, the application display name, and HOW WELL THAT NAME IS KNOWN
 *  arrive as arguments to
 *  io.github.sjtrotter.impl.portal.Smartcard1.AcquireCredential. The backend renders
 *  them. It never derives them.
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
 *  docs/decisions/0002-service-owned-pin-prompt.md. A Qt/KDE backend is a whole second
 *  *.portal file selected by portals.conf, which is exactly the shape upstream uses and
 *  the reason the backend boundary is a D-Bus interface rather than a vtable; see
 *  docs/decisions/0008-build-to-the-upstream-shape.md.
 *
 *  Sketch only; nothing here is implemented.
 */

/** How well the FRONTEND knows the caller, as the string the impl interface carries.
 *  The backend cannot compute this, cannot improve it, and MUST DISPLAY IT: an
 *  application name shown without saying how it was established is a lie by omission.
 *  See docs/SECURITY.md. */
typedef enum
{
	SMARTCARD_IDENTITY_VERIFIED_SANDBOXED, /**< "verified_sandboxed": Flatpak/Snap identity via
	                                            the containment framework's mediation,
	                                            treated as authenticated metadata */
	SMARTCARD_IDENTITY_DERIVED_HOST,       /**< "derived_host": a cgroup-derived desktop label,
	                                            possibly a Registry-style self-claim. A useful
	                                            label, NOT a security principal. Warn. */
	SMARTCARD_IDENTITY_UNKNOWN             /**< "unidentified": nothing trustworthy. "An
	                                            unidentified application", strongest warning,
	                                            first-use confirmation, no selection memory */
} SmartcardIdentityLevel;

/** What the frontend told this backend about the caller. Every field arrived as an
 *  argument. NONE of it is caller-supplied text, and none of it may be replaced by
 *  caller-supplied text. */
typedef struct
{
	SmartcardIdentityLevel level;
	const char* app_id;           /**< as the FRONTEND established it; "" if unidentified */
	const char* app_display_name; /**< as the FRONTEND established it. Never the caller's. */
} SmartcardCallerIdentity;

SmartcardIdentityLevel smartcard_identity_level_parse(const char* level);

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
	gboolean offer_selection_memory; /**< the FRONTEND says whether the caller asked for it
	                                      and whether the identity level permits it; the
	                                      backend only offers it and reports the answer.
	                                      THE FRONTEND, not this window, writes the
	                                      permission store. */
	const char* preselect_certificate; /**< a stable certificate id the frontend read back
	                                        from the permission store, or NULL.
	                                        PRESELECTION ONLY: the window still opens and
	                                        the user still confirms. */
} SmartcardChooserRequest;

typedef struct
{
	SmartcardCandidate* chosen; /**< NULL if the user cancelled */
	gboolean remember_selection; /**< what the user said. The frontend decides what to do
	                                  about it. */
	char* certificate_id;        /**< stable identifier for the chosen certificate, returned
	                                  to the frontend as the key it may store */
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
