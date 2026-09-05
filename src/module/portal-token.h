/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * THIS FILE IS A CONTRACT AND IS SHARED, BYTE FOR BYTE, BETWEEN TWO
 * REPOSITORIES: xdg-desktop-portal-certificate's src/module/portal-token.h and
 * xdg-desktop-portal-webauth's backend/src/tls/portal-token.h. They are the
 * same file down to the include guard and this licence line, so that a consumer
 * may include or copy either one. Changing a constant here is changing an
 * interface between two repositories; changing one copy without the other is a
 * bug both build systems will not catch.
 */
#ifndef WEBAUTH_TLS_PORTAL_TOKEN_H
#define WEBAUTH_TLS_PORTAL_TOKEN_H

/** @file
 *  THE NAMES THE CERTIFICATE PORTAL'S CLIENT-SIDE PKCS#11 MODULE MUST USE.
 *
 *  xdg-desktop-portal-certificate ships a PKCS#11 module that presents the
 *  certificate a user has granted to an application as a token, and performs
 *  the private key operations by calling the Certificate portal rather than by
 *  touching a card. A consumer reaches that module the only way WebKitGTK can
 *  be made to reach anything: a PKCS#11 URI resolved through p11-kit, as spike
 *  S2 established (docs/SPIKES.md).
 *
 *  So the two sides have to agree on the token's identity, and there is nowhere
 *  else to agree it: a URI is all that crosses. THESE STRINGS ARE THE INTERFACE.
 *
 *  WHY A TOKEN AND NOT A BROKERED SIGN. The Certificate portal's interfaces have
 *  no OpenPkcs11Endpoint, so a grant can only be used through brokered Sign -
 *  and neither WebKitGTK nor glib-networking has an external-signer seam a
 *  brokered Sign could be plugged into. A p11-kit module is the seam that does
 *  exist, because GnuTLS will load one and WebKit's network process will
 *  resolve a URI through it.
 *
 *  WHAT THE MODULE MUST DO, stated here because a consumer depends on it:
 *
 *   - present exactly one token whose CKA_LABEL is the label below, whose
 *     manufacturer and model are the strings below, so that a URI built from
 *     them names the portal and nothing else on the machine;
 *   - give the certificate, the public key and the private key THE SAME
 *     CKA_LABEL as the token, which is what makes the object= below a constant
 *     a consumer can write down before anything has been chosen;
 *   - set CKF_PROTECTED_AUTHENTICATION_PATH on that token. The portal prompts
 *     in its own window; a consumer must never be asked for the PIN, and the
 *     web-auth backend answers no PIN challenge on the portal adapter at all;
 *   - install its module configuration as the file named below, so that
 *     p11-kit's user and system module directories both work and a user can
 *     see and remove it;
 *   - expose the certificate object and the private key object under the same
 *     CKA_ID, so that swapping type=cert for type=private in the URI names the
 *     pair - which is exactly what a consumer does.
 */

#define XDG_PORTAL_CERTIFICATE_TOKEN_LABEL "Portal Certificate"
#define XDG_PORTAL_CERTIFICATE_TOKEN_MANUFACTURER "freedesktop.org"
#define XDG_PORTAL_CERTIFICATE_TOKEN_MODEL "portal-cert"

/** Every object on the token carries this as its CKA_LABEL, and it is the same
 *  string as the token's own label. See the URIs below for why it is a constant
 *  rather than the certificate's subject common name. */
#define XDG_PORTAL_CERTIFICATE_OBJECT_LABEL XDG_PORTAL_CERTIFICATE_TOKEN_LABEL

/** The p11-kit module configuration file the certificate portal installs, in
 *  $XDG_CONFIG_HOME/pkcs11/modules or $datadir/p11-kit/modules. */
#define XDG_PORTAL_CERTIFICATE_MODULE_CONFIG "xdg-desktop-portal-certificate.module"

/** The token, named and nothing more. This is what an ENUMERATING consumer
 *  wants - p11tool --list-all, or anything that walks the objects it finds.
 *  The percent encoding is the one p11-kit prints, so that a URI written by
 *  hand from `p11-kit list-modules` is the same string. */
#define XDG_PORTAL_CERTIFICATE_TOKEN_URI                                                           \
	"pkcs11:model=portal-cert;manufacturer=freedesktop.org;token=Portal%20Certificate"

/** The token AND the one object on it.
 *
 *  THE object= IS NOT DECORATION, and this was measured rather than assumed.
 *  GnuTLS's single-object import - `find_single_obj_cb()` in lib/pkcs11.c,
 *  which is what gnutls_x509_crt_import_url() and gnutls_privkey_import_url()
 *  reach, and therefore what g_tls_certificate_new_from_pkcs11_uris() and
 *  WebKitGTK reach - refuses a URI that names no object. It wants `object=`
 *  (CKA_LABEL) or `id=`, and a URI carrying only model, manufacturer, token and
 *  type fails with GNUTLS_E_PKCS11_REQUESTED_OBJECT_NOT_AVAILABLE before any
 *  chooser is shown. Enumeration accepts either form; the single-object import
 *  does not, so the contract carries object= and an enumerating consumer that
 *  does not want it uses XDG_PORTAL_CERTIFICATE_TOKEN_URI above.
 *
 *  This is also why the module's CKA_LABEL is a constant and not the subject
 *  common name: a consumer has to write these URIs down before anything has
 *  been chosen, and it cannot know a common name in advance. A token holding
 *  exactly one credential can be allowed to name it after itself; the
 *  certificate's real identity is in its DER. */
#define XDG_PORTAL_CERTIFICATE_OBJECT_URI                                                          \
	XDG_PORTAL_CERTIFICATE_TOKEN_URI ";object=Portal%20Certificate"

#define XDG_PORTAL_CERTIFICATE_CERT_URI XDG_PORTAL_CERTIFICATE_OBJECT_URI ";type=cert"
#define XDG_PORTAL_CERTIFICATE_KEY_URI XDG_PORTAL_CERTIFICATE_OBJECT_URI ";type=private"

#endif /* WEBAUTH_TLS_PORTAL_TOKEN_H */
