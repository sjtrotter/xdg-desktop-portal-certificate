/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 *
 * THIS FILE IS A CONTRACT AND IS SHARED WITH ANOTHER REPOSITORY. It is the same
 * file as webauth-service's backend/src/tls/portal-token.h, down to the include
 * guard, so that a consumer may include or copy either one. Only the licence
 * line differs: that copy is GPL-2.0-or-later and this one is this project's
 * LGPL-2.1-or-later, because a header compiled into this library cannot carry a
 * stronger licence than the library. The constants below are byte-identical and
 * must stay that way; changing one is changing an interface between two
 * repositories.
 */
#ifndef WEBAUTH_TLS_PORTAL_TOKEN_H
#define WEBAUTH_TLS_PORTAL_TOKEN_H

/** @file
 *  THE NAMES THE CERTIFICATE PORTAL'S CLIENT-SIDE PKCS#11 MODULE MUST USE.
 *
 *  This header is a contract with a component in another repository:
 *  xdg-desktop-portal-certificate ships (will ship) a PKCS#11 module that
 *  presents the certificates a user has granted to an application as a token,
 *  and performs the private key operations by calling the Certificate portal
 *  rather than by touching a card. This backend reaches that module the only way
 *  WebKitGTK can be made to reach anything: a PKCS#11 URI resolved through
 *  p11-kit, as spike S2 established (docs/SPIKES.md).
 *
 *  So the two sides have to agree on the token's identity, and there is nowhere
 *  else to agree it: a URI is all that crosses. THESE STRINGS ARE THE INTERFACE.
 *  Changing one is changing an interface between two repositories.
 *
 *  WHY A TOKEN AND NOT A BROKERED SIGN. The Certificate portal's branch
 *  interface has no OpenPkcs11Endpoint, so a grant can only be used through
 *  brokered Sign - and neither WebKitGTK nor glib-networking has an
 *  external-signer seam a brokered Sign could be plugged into. A p11-kit module
 *  is the seam that does exist, because GnuTLS will load one and WebKit's
 *  network process will resolve a URI through it. See
 *  docs/decisions/0007-certificate-adapter.md.
 *
 *  WHAT THE MODULE MUST DO, stated here because this backend depends on it:
 *
 *   - present exactly one token whose CKA_LABEL is the label below, whose
 *     manufacturer and model are the strings below, so that a URI built from
 *     them names the portal and nothing else on the machine;
 *   - set CKF_PROTECTED_AUTHENTICATION_PATH on that token. The portal prompts
 *     in its own window; a backend must never be asked for the PIN, and this
 *     backend answers no PIN challenge on the portal adapter at all;
 *   - install its module configuration as the file named below, so that
 *     p11-kit's user and system module directories both work and a user can
 *     see and remove it;
 *   - expose the certificate object and the private key object under the same
 *     CKA_ID, so that swapping type=cert for type=private in the URI names the
 *     pair - which is exactly what this backend does.
 */

#define XDG_PORTAL_CERTIFICATE_TOKEN_LABEL "Portal Certificate"
#define XDG_PORTAL_CERTIFICATE_TOKEN_MANUFACTURER "freedesktop.org"
#define XDG_PORTAL_CERTIFICATE_TOKEN_MODEL "portal-cert"

/** The p11-kit module configuration file the certificate portal installs, in
 *  $XDG_CONFIG_HOME/pkcs11/modules or $datadir/p11-kit/modules. */
#define XDG_PORTAL_CERTIFICATE_MODULE_CONFIG "xdg-desktop-portal-certificate.module"

/** The URI this backend builds from the constants above. The percent encoding is
 *  the one p11-kit prints, so that a URI written by hand from `p11-kit
 *  list-modules` is the same string. */
#define XDG_PORTAL_CERTIFICATE_TOKEN_URI                                                           \
	"pkcs11:model=portal-cert;manufacturer=freedesktop.org;token=Portal%20Certificate"

#define XDG_PORTAL_CERTIFICATE_CERT_URI XDG_PORTAL_CERTIFICATE_TOKEN_URI ";type=cert"
#define XDG_PORTAL_CERTIFICATE_KEY_URI XDG_PORTAL_CERTIFICATE_TOKEN_URI ";type=private"

#endif /* WEBAUTH_TLS_PORTAL_TOKEN_H */
