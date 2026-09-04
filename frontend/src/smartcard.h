/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SMARTCARD_FRONTEND_SMARTCARD_H
#define SMARTCARD_FRONTEND_SMARTCARD_H

#include <glib.h>

/** @file
 *  The FRONTEND's implementation of io.github.sjtrotter.portal.Smartcard1.
 *
 *  One file per portal, exactly as xdg-desktop-portal does it (desktop-portal/camera.c,
 *  desktop-portal/usb.c, ...). At upstreaming this file becomes
 *  xdg-desktop-portal/desktop-portal/smartcard.c; see docs/UPSTREAMING.md.
 *
 *  WHAT THE FRONTEND OWNS, and what this file therefore does:
 *
 *   - CALLER IDENTITY. Every method resolves the peer to an app id before anything else
 *     happens (app-info.h). The backend is told the answer; it never derives one.
 *   - POLICY. Purpose validation -- there is no "any" -- option validation, the lifetime
 *     ceiling, which operations a purpose may ask for, the mechanism allow-list, and
 *     rate limits per caller and globally.
 *   - PERMISSIONS. Remembered certificate SELECTION, through the permission store
 *     (permission-store.h). Never remembered authorisation, never a PIN.
 *   - REQUEST AND SESSION LIFECYCLE (request.h, session.h) and the grant registry
 *     (grant-registry.h): grant identity, expiry, ownership, delegation, invalidation.
 *   - BACKEND SELECTION (portal-impl.h) and the call itself, with app_id attached.
 *
 *  WHAT IT DOES NOT DO: draw a window, load a PKCS#11 module, touch a card, hold a
 *  token session, or see a PIN. All of that is the backend's, because the backend is
 *  the part that is allowed to know what a desktop looks like and what a reader is
 *  plugged into. See docs/ARCHITECTURE.md for the responsibility table.
 *
 *  THE CORE CONTRACT IS CREDENTIAL SELECTION PLUS BROKERED OPERATIONS. AcquireCredential
 *  returns a grant; Sign performs the work in the backend, never in the application.
 *  OpenPkcs11Endpoint is an EXPERIMENTAL compatibility extension for consumers that can
 *  only load a module, is never returned automatically, and is backed by a synthetic
 *  facade rather than the card forwarded. See
 *  docs/decisions/0007-brokered-operations-are-the-core.md.
 *
 *  Sketch only; nothing here is implemented.
 */

/** The frontend's public identity. Our stand-in for org.freedesktop.portal.Desktop and
 *  /org/freedesktop/portal/desktop. Applications talk to this and to nothing else. */
#define SMARTCARD_BUS_NAME "io.github.sjtrotter.portal.Desktop"
#define SMARTCARD_OBJECT_PATH "/io/github/sjtrotter/portal/desktop"
#define SMARTCARD_INTERFACE "io.github.sjtrotter.portal.Smartcard1"
#define SMARTCARD_INTERFACE_VERSION 1u

/** The interface the frontend requires of a backend. A *.portal file that does not list
 *  this string does not implement this portal, and the frontend will not call it. */
#define SMARTCARD_IMPL_INTERFACE "io.github.sjtrotter.impl.portal.Smartcard1"

/** Error names. These appear both as D-Bus errors on the initial call and as
 *  results["error"] on a Request.Response of 2. Incorrect PIN, blocked PIN, cancelled
 *  prompt, device error and token removal are ALWAYS distinguished: collapsing them is
 *  how a user blocks a card while being told "authentication failed".
 *
 *  A backend reports a CONDITION; the frontend chooses the error name the application
 *  sees. A backend cannot invent an error name, and cannot make the frontend say
 *  "cancelled by the user" about something the user never saw. */
#define SMARTCARD_ERROR_PREFIX SMARTCARD_INTERFACE ".Error"
#define SMARTCARD_ERROR_NO_TOKEN SMARTCARD_ERROR_PREFIX ".NoToken"
#define SMARTCARD_ERROR_TOKEN_ABSENT SMARTCARD_ERROR_PREFIX ".TokenAbsent"
#define SMARTCARD_ERROR_TOKEN_REMOVED SMARTCARD_ERROR_PREFIX ".TokenRemoved"
#define SMARTCARD_ERROR_NO_MATCHING_CERTIFICATE SMARTCARD_ERROR_PREFIX ".NoMatchingCertificate"
#define SMARTCARD_ERROR_PIN_INCORRECT SMARTCARD_ERROR_PREFIX ".PinIncorrect"
#define SMARTCARD_ERROR_PIN_LOCKED SMARTCARD_ERROR_PREFIX ".PinLocked"
#define SMARTCARD_ERROR_INTERACTION_REQUIRED SMARTCARD_ERROR_PREFIX ".InteractionRequired"
#define SMARTCARD_ERROR_NO_DISPLAY SMARTCARD_ERROR_PREFIX ".NoDisplay"
#define SMARTCARD_ERROR_UNSUPPORTED_MECHANISM SMARTCARD_ERROR_PREFIX ".UnsupportedMechanism"
#define SMARTCARD_ERROR_GRANT_EXPIRED SMARTCARD_ERROR_PREFIX ".GrantExpired"
#define SMARTCARD_ERROR_NOT_PERMITTED SMARTCARD_ERROR_PREFIX ".NotPermitted"
#define SMARTCARD_ERROR_RATE_LIMITED SMARTCARD_ERROR_PREFIX ".RateLimited"
#define SMARTCARD_ERROR_DEVICE_ERROR SMARTCARD_ERROR_PREFIX ".DeviceError"
/** No backend implements the impl interface, or the one selected will not start. The
 *  old name for "no p11-kit, no pcscd, no module" -- which is now something the BACKEND
 *  discovers and reports, because the frontend does not load modules. */
#define SMARTCARD_ERROR_BACKEND_UNAVAILABLE SMARTCARD_ERROR_PREFIX ".BackendUnavailable"

/** The purposes. There is deliberately NO "any": a request that will not say what it is
 *  for cannot be described to the user in the system's own words, cannot be given a
 *  consent policy, and cannot be filtered. The FRONTEND validates this before any
 *  backend is called; the backend renders it in its own words. Each purpose carries its
 *  own consent policy; see ../../backends/gtk/src/broker/operations.h. */
typedef enum
{
	SMARTCARD_PURPOSE_CLIENT_AUTH, /**< one consent per short grant, bound to app+cert+context */
	SMARTCARD_PURPOSE_SIGNING,     /**< per-operation consent by default, digest shown */
	SMARTCARD_PURPOSE_EMAIL,       /**< session grant defensible; bulk behaviour must be explicit */
	SMARTCARD_PURPOSE_SSH          /**< its own policy; NOT "signing with extra steps" */
} SmartcardPurpose;

/** Parse and validate a caller's purpose string. Rejects anything not in the list, and
 *  in particular rejects "any" and the empty string. */
gboolean smartcard_purpose_parse(const char* text, SmartcardPurpose* out);

typedef struct SmartcardFrontend SmartcardFrontend;

/** Claim SMARTCARD_BUS_NAME, export SMARTCARD_OBJECT_PATH, load the backend
 *  configuration (portal-impl.h) and connect to the permission store
 *  (permission-store.h). Does NOT require a backend to be running: backends are D-Bus
 *  activated on first use, exactly as upstream does it. */
SmartcardFrontend* smartcard_frontend_new(gboolean replace, GError** error);

/** Run until idle with no live grants, or until told to stop. A per-user service that
 *  never exits is a per-user service holding a card session nobody asked it to hold. */
int smartcard_frontend_run(SmartcardFrontend* frontend);

/** Shut down: close every session (which closes the backend's), invalidate every grant
 *  with reason "service_shutdown", and drop the backend proxies. */
void smartcard_frontend_shutdown(SmartcardFrontend* frontend);

/** Rate limits, per caller and globally, on requests and on operations. Applied by the
 *  FRONTEND because they are policy and because the frontend is the only side that knows
 *  which application is asking. A backend has no way to distinguish two applications
 *  from one application asking twice. */
gboolean smartcard_frontend_rate_limit_ok(SmartcardFrontend* frontend, const char* app_id,
                                          const char* what);

#endif /* SMARTCARD_FRONTEND_SMARTCARD_H */
