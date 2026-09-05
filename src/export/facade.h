/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */
#ifndef CERTIFICATE_EXPORT_FACADE_H
#define CERTIFICATE_EXPORT_FACADE_H

/** @file
 *  THE FACADE IS NOT BEING BUILT. THE MODULE IN src/module/ IS.
 *
 *  This file used to describe a synthetic PKCS#11 facade served over a socket by
 *  a helper process beside this backend, reached through an `OpenPkcs11Endpoint`
 *  that is on neither interface. The consumers it existed for -- WebKitGTK
 *  through glib-networking, Firefox and Thunderbird through NSS -- are served
 *  instead by a PKCS#11 module that runs in THEIR OWN process and forwards to
 *  the PUBLIC portal interface over D-Bus:
 *
 *      src/module/                    the module
 *      src/module/portal-token.h      the constants it presents
 *      docs/decisions/0011-client-side-pkcs11-module.md   why, and what it does
 *                                                         not solve
 *
 *  The two designs are not variations on each other. The facade was a server
 *  defending a boundary against a hostile peer over a wire protocol, and was
 *  budgeted as such. The module is a client on the application's own side of a
 *  boundary the portal enforces; a compromised application that abuses it can
 *  call Sign as itself, which it could already do over D-Bus, and nothing more.
 *
 *  The facade's requirements list has not been deleted -- it is in
 *  docs/SECURITY.md and in 0006 -- and it becomes the acceptance criteria again
 *  if anyone ever adds an fd-returning method. Nothing in this repository is
 *  waiting for one.
 */

#endif /* CERTIFICATE_EXPORT_FACADE_H */
