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

/** A private context thread dispatches portal signals while PKCS#11 callers wait independently of the application's loop. */

typedef struct _PortalClient PortalClient;

/** Watch the frontend without activation; capabilities are probed on the next use. */
PortalClient* portal_client_new(void);

void portal_client_free(PortalClient* client);

/** Cancel and close outstanding requests before C_Finalize waits for their callers. */
void portal_client_cancel(PortalClient* client);

gboolean portal_client_available(PortalClient* client);

/** Caller owns the capability snapshot. */
GStrv portal_client_dup_mechanisms(PortalClient* client);

/** Blocks for the chooser; user refusal returns PKCS11_PORTAL_ERROR_CANCELLED. */
PortalGrant* portal_client_acquire(PortalClient* client, GError** error);

/** @data is the digest named by @hash. */
gboolean portal_client_sign(PortalClient* client, const PortalGrant* grant,
                            const char* mechanism, const char* hash, const char* mgf,
                            gboolean have_salt_length, guint32 salt_length, const guint8* data,
                            gsize size, GBytes** signature, GError** error);

gboolean portal_client_decrypt(PortalClient* client, const PortalGrant* grant, const char* hash,
                               const char* mgf1_hash, GBytes* label, const guint8* data,
                               gsize size, GBytes** plaintext, GError** error);

/** Session.Close() releases the grant; an absent grant succeeds. */
void portal_client_release(PortalClient* client, const PortalGrant* grant);

/** Invalidation uses its own lock, so PKCS#11 callers may hold module_lock across portal calls. */
gboolean portal_client_grant_gone(PortalClient* client, const PortalGrant* grant);

/** Exact executable names exclude recursive frontend and certificate-backend calls; the environment flag excludes other consumers. */
gboolean portal_client_self_excluded(void);

gboolean portal_program_is_excluded(const char* program);

#endif
