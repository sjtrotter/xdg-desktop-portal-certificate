/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef PKCS11_PORTAL_PORTAL_H
#define PKCS11_PORTAL_PORTAL_H

#include <gio/gio.h>
#include <glib.h>

#include "grant.h"

/** @file
 *  The module's client of org.freedesktop.portal.experimental.Certificate.
 *
 *  A PKCS#11 call arrives on whatever thread the application felt like, and the
 *  portal answers Request-shaped calls with a signal. So the client owns a
 *  thread running its own GMainContext: signal subscriptions are made there and
 *  dispatched there, and the PKCS#11 caller blocks on a condition variable
 *  rather than on the application's main loop, which may not exist and is not
 *  ours to run.
 *
 *  Plain method calls -- GetCapabilities, ReleaseGrant -- are made with
 *  g_dbus_connection_call_sync() on the calling thread, which needs no context
 *  of its own.
 */

typedef struct _PortalClient PortalClient;

/** Connect, and probe GetCapabilities without letting D-Bus activate anything:
 *  a module loaded into every p11-kit consumer on the machine must not start
 *  the desktop portal merely by being listed. Never fails: a client that could
 *  not reach the portal reports itself unavailable, which is how a token that
 *  is not present is spelled. */
PortalClient* portal_client_new(void);

void portal_client_free(PortalClient* client);

/** Whether the interface answered. FALSE means no portal, no certificate
 *  backend, or the experimental gate is off -- indistinguishable by design. */
gboolean portal_client_available(PortalClient* client);

/** The portal's mechanism names, from GetCapabilities. */
const char* const* portal_client_mechanisms(PortalClient* client);

/** CreateSession followed by AcquireCredential, blocking until the user has
 *  answered the chooser. Returns NULL with PKCS11_PORTAL_ERROR_CANCELLED when
 *  the user said no. */
PortalGrant* portal_client_acquire(PortalClient* client, GError** error);

/** One brokered Sign. @data is the digest named by @hash. */
gboolean portal_client_sign(PortalClient* client, const PortalGrant* grant,
                            const char* mechanism, const char* hash, const char* mgf,
                            gboolean have_salt_length, guint32 salt_length, const guint8* data,
                            gsize size, GBytes** signature, GError** error);

/** One brokered Decrypt, RSA-OAEP only. */
gboolean portal_client_decrypt(PortalClient* client, const PortalGrant* grant, const char* hash,
                               const char* mgf1_hash, GBytes* label, const guint8* data,
                               gsize size, GBytes** plaintext, GError** error);

/** ReleaseGrant. Releasing a grant that is already gone succeeds. */
void portal_client_release(PortalClient* client, const PortalGrant* grant);

/** Whether GrantInvalidated has named this grant's session. Read from the
 *  PKCS#11 caller's thread; the signal handler only ever writes it, and never
 *  takes the module lock, so a caller may hold that lock across a portal
 *  call. */
gboolean portal_client_grant_gone(PortalClient* client, const PortalGrant* grant);

/** Whether this process must not talk to the portal at all: the certificate
 *  backend and the portal frontend would recurse into themselves. */
gboolean portal_client_self_excluded(void);

#endif /* PKCS11_PORTAL_PORTAL_H */
