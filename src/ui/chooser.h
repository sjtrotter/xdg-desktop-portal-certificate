/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xdg-desktop-portal-certificate
 * Copyright (C) 2026 the xdg-desktop-portal-certificate authors
 */
#ifndef CERTIFICATE_UI_CHOOSER_H
#define CERTIFICATE_UI_CHOOSER_H

#include <gio/gio.h>
#include <glib.h>

#include "../certificate.h"
#include "../tokens/discovery.h"

/** @file
 *  The trusted chooser. THIS WINDOW IS THE CONSENT DECISION.
 *
 *  DRAWN BY THE BACKEND, FROM FACTS THE FRONTEND ESTABLISHED. This is the
 *  division upstream makes for every portal that asks a question, and it is the
 *  one that makes the answer trustworthy: the side that knows who is calling is
 *  not the side that draws the window, so the window cannot be talked into
 *  naming the wrong application by the application. app_id and HOW WELL THAT
 *  NAME IS KNOWN (the app_identity_level option) arrive as arguments. The
 *  backend renders them. It never derives them.
 *
 *  NOTE WHAT DOES NOT ARRIVE. The branch interface passes app_id and
 *  app_identity_level and nothing else about the caller: there is no
 *  app_display_name option, so the human-readable name is this backend's to
 *  produce from the app id (a desktop file lookup) or to omit. There is also no
 *  `context` option -- the earlier sketch's "requested destination host" hint
 *  does not exist on the wire, and the only caller-supplied text that does is
 *  `reason`.
 *
 *  Not the PIN prompt. The PIN proves the user was present and knew the PIN; it
 *  does not tell them which application asked, for what, or how long the answer
 *  lasts. A design where the PIN prompt is the only user-visible moment has
 *  taught the user to type their PIN whenever asked, which is precisely what an
 *  attacker needs.
 *
 *  NOTHING CALLER-SUPPLIED MAY OCCUPY THE TRUSTED IDENTITY POSITION. Not
 *  reason, not a title, not the token label, not the certificate subject. A
 *  caller that sends reason "Microsoft Login" must not get a window that reads
 *  as Microsoft's: the reason is escaped, collapsed to one line, truncated, and
 *  rendered quoted under a label that says the application wrote it.
 *
 *  ACCESSIBILITY IS AN ACCEPTANCE CRITERION, NOT POLISH. A security dialog a
 *  screen-reader user cannot navigate is a dialog that user cannot give
 *  informed consent through. Complete keyboard-only operation, Escape cancels,
 *  meaningful focus order, and no information carried by colour alone --
 *  including "expired", which is a word in the row and not a red tint.
 */

typedef struct
{
	const CertificateCallerIdentity* caller;
	CertificatePurpose purpose;
	gboolean may_sign;
	gboolean may_decrypt;
	guint32 lifetime_seconds;
	const char* reason;              /**< UNTRUSTED. Displayed labelled, subordinate. Never logged. */
	gboolean offer_selection_memory; /**< whether to draw the "use this certificate next time"
	                                      checkbox at all. It comes from the impl interface's
	                                      allow_selection_memory option, which is the FRONTEND's
	                                      effective answer: the application asked for it AND its
	                                      identity level permits it. False means DO NOT OFFER --
	                                      the frontend discards remember_selection in that case,
	                                      so a checkbox drawn anyway is a promise nothing keeps.
	                                      THE FRONTEND, not this window, writes the permission
	                                      store. */
	const char* preselect_certificate; /**< a stable certificate id the frontend read back from the
	                                        permission store, or NULL. PRESELECTION ONLY: the window
	                                        still opens and the user still confirms. */
} CertificateChooserRequest;

typedef struct
{
	CertificateCandidate* chosen; /**< NULL if the user cancelled */
	gboolean remember_selection;
} CertificateChooserResult;

typedef void (*CertificateChooserDone)(const CertificateChooserResult* result, gpointer user_data);

/** Show the chooser. @parent_window uses the portal window-identifier
 *  convention. AN INVALID OR EXPIRED PARENT MUST NOT FAIL THE REQUEST: it
 *  degrades to an unparented, service-controlled window. @activation_token
 *  authorises focus. */
void certificate_chooser_show(const char* parent_window, const char* activation_token,
                              GPtrArray* candidates, const CertificateChooserRequest* request,
                              GCancellable* cancellable, CertificateChooserDone done,
                              gpointer user_data);

#endif /* CERTIFICATE_UI_CHOOSER_H */
