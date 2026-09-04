/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SMARTCARD_DBUS_SERVICE_H
#define SMARTCARD_DBUS_SERVICE_H

#include <glib.h>

/** @file
 *  The D-Bus transaction layer: io.github.sjtrotter.Smartcard1.
 *
 *  Owns the bus name and exports /io/github/sjtrotter/Smartcard1. The interface is
 *  described in data/io.github.sjtrotter.Smartcard1.xml and explained in
 *  docs/INTERFACE.md.
 *
 *  THE CORE CONTRACT IS CREDENTIAL SELECTION PLUS BROKERED OPERATIONS. AcquireCredential
 *  returns a grant; Sign performs the work inside this service. OpenPkcs11Endpoint is an
 *  EXPERIMENTAL compatibility extension for consumers that can only load a module, is
 *  never returned automatically, and is backed by a synthetic facade rather than the
 *  card forwarded. See docs/decisions/0007-brokered-operations-are-the-core.md.
 *
 *  Version 0 is ONE service. There is no org.freedesktop.impl.portal.* backend ABI:
 *  imitating a portal's names confers none of a portal's properties while doubling the
 *  D-Bus surface, activation and crash handling, versioning obligations, packaging and
 *  transaction-lifetime bugs. The internal seam -- transaction layer, chooser/PIN
 *  interface, GTK4 implementation -- is a C vtable, which is where a split would go.
 *
 *  Sketch only; nothing here is implemented.
 */

#define SMARTCARD_BUS_NAME "io.github.sjtrotter.Smartcard1"
#define SMARTCARD_OBJECT_PATH "/io/github/sjtrotter/Smartcard1"
#define SMARTCARD_INTERFACE_VERSION 1u

/** Error names. These appear both as D-Bus errors on the initial call and as
 *  results["error"] on a Request.Response of 2. Incorrect PIN, blocked PIN, cancelled
 *  prompt, device error and token removal are ALWAYS distinguished: collapsing them is
 *  how a user blocks a card while being told "authentication failed". */
#define SMARTCARD_ERROR_NO_TOKEN SMARTCARD_BUS_NAME ".Error.NoToken"
#define SMARTCARD_ERROR_TOKEN_ABSENT SMARTCARD_BUS_NAME ".Error.TokenAbsent"
#define SMARTCARD_ERROR_TOKEN_REMOVED SMARTCARD_BUS_NAME ".Error.TokenRemoved"
#define SMARTCARD_ERROR_NO_MATCHING_CERTIFICATE SMARTCARD_BUS_NAME ".Error.NoMatchingCertificate"
#define SMARTCARD_ERROR_PIN_INCORRECT SMARTCARD_BUS_NAME ".Error.PinIncorrect"
#define SMARTCARD_ERROR_PIN_LOCKED SMARTCARD_BUS_NAME ".Error.PinLocked"
#define SMARTCARD_ERROR_INTERACTION_REQUIRED SMARTCARD_BUS_NAME ".Error.InteractionRequired"
#define SMARTCARD_ERROR_NO_DISPLAY SMARTCARD_BUS_NAME ".Error.NoDisplay"
#define SMARTCARD_ERROR_UNSUPPORTED_MECHANISM SMARTCARD_BUS_NAME ".Error.UnsupportedMechanism"
#define SMARTCARD_ERROR_GRANT_EXPIRED SMARTCARD_BUS_NAME ".Error.GrantExpired"
#define SMARTCARD_ERROR_NOT_PERMITTED SMARTCARD_BUS_NAME ".Error.NotPermitted"
#define SMARTCARD_ERROR_RATE_LIMITED SMARTCARD_BUS_NAME ".Error.RateLimited"
#define SMARTCARD_ERROR_DEVICE_ERROR SMARTCARD_BUS_NAME ".Error.DeviceError"
#define SMARTCARD_ERROR_BACKEND_UNAVAILABLE SMARTCARD_BUS_NAME ".Error.BackendUnavailable"

/** The purposes. There is deliberately NO "any": a request that will not say what it is
 *  for cannot be described to the user in this service's own words, cannot be given a
 *  consent policy, and cannot be filtered. Each purpose carries its own consent policy;
 *  see src/broker/operations.h. */
typedef enum
{
	SMARTCARD_PURPOSE_CLIENT_AUTH, /**< one consent per short grant, bound to app+cert+context */
	SMARTCARD_PURPOSE_SIGNING,     /**< per-operation consent by default, digest shown */
	SMARTCARD_PURPOSE_EMAIL,       /**< session grant defensible; bulk behaviour must be explicit */
	SMARTCARD_PURPOSE_SSH          /**< its own policy; NOT "signing with extra steps" */
} SmartcardPurpose;

typedef struct SmartcardService SmartcardService;

/** Claim the bus name and export the interface. @replace takes the name from a running
 *  instance. Fails with SMARTCARD_ERROR_BACKEND_UNAVAILABLE when there is no session
 *  bus, no p11-kit, or no usable module configuration -- checked at startup so a caller
 *  fails early and clearly rather than mid-handshake. */
SmartcardService* smartcard_service_new(gboolean replace, GError** error);

/** Run until idle with no live grants, or until told to stop. A per-user service that
 *  never exits is a per-user service holding a card session nobody asked it to hold. */
int smartcard_service_run(SmartcardService* service);

/** Shut down: invalidate every grant (reason "service_shutdown"), close every session,
 *  log out where the token permits, poison every endpoint, reap every helper. */
void smartcard_service_shutdown(SmartcardService* service);

#endif /* SMARTCARD_DBUS_SERVICE_H */
