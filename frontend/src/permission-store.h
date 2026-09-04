/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SMARTCARD_FRONTEND_PERMISSION_STORE_H
#define SMARTCARD_FRONTEND_PERMISSION_STORE_H

#include <glib.h>

/** @file
 *  Remembered certificate SELECTION, in the desktop's own permission store.
 *
 *  Uses the REAL org.freedesktop.impl.portal.PermissionStore at
 *  /org/freedesktop/impl/portal/PermissionStore when one is present -- it is a
 *  general-purpose, desktop-owned, free-form store that xdg-desktop-portal already
 *  relies on for exactly this class of decision, and reimplementing it would mean the
 *  user's revocation UI does not list us. If it is absent, selection memory is simply
 *  unavailable: it is a convenience, and the fallback for a missing convenience is to do
 *  without, never to invent a private store the user cannot see.
 *    https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.PermissionStore.html
 *
 *  THE FRONTEND OWNS THIS. The backend never reads or writes the permission store, for
 *  the same reason it never derives an app id: the key is the app id, and the app id is
 *  the frontend's. The backend is TOLD which certificate to preselect and REPORTS which
 *  one the user chose; the frontend decides whether to store that.
 *
 *  WHAT IS STORED, precisely: a stable certificate identifier, under a resource id built
 *  from the purpose and the filter context, for one app id. That is all.
 *
 *    table       "smartcard"
 *    id          "cert-selection:<purpose>:<filter-digest>"
 *    app         the app id -- NEVER an empty one, and never a level-UNKNOWN caller
 *    permissions { "certificate:<stable-id>" }
 *
 *  THREE THINGS MUST NEVER BE CONFLATED, and only the first exists here:
 *    1. remember WHICH CERTIFICATE was selected -- this;
 *    2. token login caching -- hardware behaviour nobody here controls or may present as
 *       a feature;
 *    3. remembered AUTHORISATION to use the key -- deliberately absent.
 *
 *  SO: a stored selection PRESELECTS. It never skips the chooser, never skips a PIN, is
 *  unavailable to callers whose identity could not be verified, is offered only when the
 *  caller passed allow_selection_memory AND the user accepted, and is listed and
 *  revocable in the desktop's own permission UI because it lives where that UI looks.
 *
 *  There is no "remember PIN" and there never will be. No entry here holds a PIN, a
 *  PKCS#11 URI, a card serial or a certificate subject.
 *
 *  Sketch only; nothing here is implemented.
 */

#define SMARTCARD_PERMISSION_STORE_NAME "org.freedesktop.impl.portal.PermissionStore"
#define SMARTCARD_PERMISSION_STORE_PATH "/org/freedesktop/impl/portal/PermissionStore"
#define SMARTCARD_PERMISSION_TABLE "smartcard"

/** Build the resource id for a request: purpose plus a digest of the certificate filter,
 *  so that "sign in to this site" and "sign a document" remember different answers and a
 *  changed filter does not silently reuse an old one. The digest covers only fields the
 *  caller supplied; nothing about the card goes into the key. */
char* smartcard_permission_resource_id(const char* purpose, GVariant* certificate_filter);

/** Look up the remembered certificate for @app_id, or NULL. Returns NULL immediately,
 *  without a bus round trip, for an empty app id or an unverified caller. */
char* smartcard_permission_get_selection(const char* app_id, const char* resource_id);

/** Store a selection the user explicitly accepted. Never called from a backend result
 *  alone: the backend reports remember_selection, the frontend checks that the caller
 *  asked for it, that the identity level permits it, and that the user said yes. */
void smartcard_permission_set_selection(const char* app_id, const char* resource_id,
                                        const char* certificate_id);

/** Forget one, for the frontend's own revocation path. The desktop's permission UI can
 *  also delete it directly, which is the point of using the shared store. */
void smartcard_permission_forget(const char* app_id, const char* resource_id);

#endif /* SMARTCARD_FRONTEND_PERMISSION_STORE_H */
