/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SMARTCARD_FRONTEND_APP_INFO_H
#define SMARTCARD_FRONTEND_APP_INFO_H

#include <glib.h>

/** @file
 *  Who is asking. THE FRONTEND ESTABLISHES THIS AND NOBODY ELSE.
 *
 *  This is the single most important consequence of the frontend/backend split, and the
 *  reason the split is worth its cost. Before it, a service drew a window naming an
 *  application it had inferred itself. Now: the frontend resolves the peer, and every
 *  impl call carries the answer as an ARGUMENT. The backend never asks the bus who is
 *  calling, because the answer would be "the frontend".
 *
 *  Modelled on xdg-desktop-portal's shared/xdp-app-info*.c, which tries each mechanism
 *  in order and falls back to the host:
 *
 *    1. FLATPAK      -- the instance's metadata, obtained through the containment
 *                       framework's mediation. Authenticated metadata.
 *                       (shared/xdp-app-info-flatpak.c)
 *    2. SNAP         -- snapd's own answer for the peer's pid.
 *                       (shared/xdp-app-info-snap.c)
 *    3. HOST         -- a cgroup-derived desktop identity for an unsandboxed peer, plus
 *                       the Registry-style claim below. A USEFUL LABEL, NOT A SECURITY
 *                       PRINCIPAL. (shared/xdp-app-info-host.c)
 *    4. nothing      -- an unidentified application, said in those words.
 *
 *  THE REGISTRY-STYLE CLAIM. Upstream lets an unsandboxed peer associate itself with a
 *  desktop-file app id through org.freedesktop.host.portal.Registry, and its own
 *  documentation warns the mechanism is expected to change:
 *    https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.host.portal.Registry.html
 *  A claim is a claim. It is recorded, it is DISPLAYED AS UNVERIFIED, and it never keys
 *  selection memory on its own.
 *
 *  EXECUTABLE PATHS ARE NOT IDENTITIES. A same-UID process can execute another path,
 *  manipulate launch context, or connect directly to the bus. /proc/$pid/exe is a hint.
 *
 *  Sketch only; nothing here is implemented.
 */

/** How much the frontend actually knows about who is asking. THIS TRAVELS TO THE BACKEND
 *  AND THE BACKEND MUST DISPLAY IT: an app id shown without its honesty level is a lie
 *  by omission. See docs/SECURITY.md. */
typedef enum
{
	SMARTCARD_IDENTITY_VERIFIED_SANDBOXED, /**< Flatpak/Snap identity via the containment
	                                            framework's mediation: authenticated metadata */
	SMARTCARD_IDENTITY_DERIVED_HOST,       /**< cgroup-derived desktop label, possibly with a
	                                            Registry-style claim: a useful label, NOT a
	                                            security principal. Warn. */
	SMARTCARD_IDENTITY_UNKNOWN             /**< nothing trustworthy: "an unidentified
	                                            application", strongest warning, first-use
	                                            confirmation, no selection memory */
} SmartcardIdentityLevel;

typedef struct
{
	SmartcardIdentityLevel level;
	char* app_id;           /**< what goes into every impl call and every permission-store key */
	char* app_display_name; /**< as THIS SERVICE established it. Never caller-supplied text. */
	char* unique_bus_name;  /**< what a grant is actually bound to */
	gboolean sandboxed;
	gboolean id_was_claimed; /**< came from a Registry-style claim rather than from mediation */
} SmartcardAppInfo;

/** Resolve the peer of @invocation. Asynchronous because the mechanisms are: Flatpak
 *  metadata is a file read, snapd is a socket round trip. Never blocks the main loop,
 *  and never trusts anything the caller said about itself.
 *
 *  A failure to identify is NOT an error: it produces SMARTCARD_IDENTITY_UNKNOWN, which
 *  the user is then told about in the strongest terms the design has. */
void smartcard_app_info_resolve(GDBusMethodInvocation* invocation, GCancellable* cancellable,
                                GAsyncReadyCallback callback, gpointer user_data);

SmartcardAppInfo* smartcard_app_info_finish(GAsyncResult* result, GError** error);

/** The string form used in impl calls and permission-store lookups. For an unidentified
 *  caller this is the empty string -- the same convention upstream uses for an
 *  unsandboxed caller with no known app id -- and an empty app id NEVER keys stored
 *  state. */
const char* smartcard_app_info_get_id(const SmartcardAppInfo* info);

/** The honesty level as the string the impl interface carries:
 *  "verified_sandboxed" | "derived_host" | "unidentified". */
const char* smartcard_app_info_level_string(const SmartcardAppInfo* info);

void smartcard_app_info_free(SmartcardAppInfo* info);

#endif /* SMARTCARD_FRONTEND_APP_INFO_H */
