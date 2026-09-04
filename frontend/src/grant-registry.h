/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SMARTCARD_FRONTEND_GRANT_REGISTRY_H
#define SMARTCARD_FRONTEND_GRANT_REGISTRY_H

#include <glib.h>

#include "app-info.h"
#include "smartcard.h"

/** @file
 *  Live grants: what was authorised, by whom, for how long, and when it dies.
 *
 *  THE FRONTEND OWNS THE GRANT REGISTRY. This is the one allocation of responsibility
 *  the split forced a decision on, and it is decided here and in docs/ARCHITECTURE.md:
 *
 *    FRONTEND: grant IDENTITY (the session object and its handle), the binding to an
 *              app id and an owning connection, the operation set, the mechanism
 *              allow-list, expiry and renewal, rate limits, delegation and the orphan
 *              grace period, invalidation and the signals that announce it.
 *    BACKEND:  the TOKEN SESSION standing behind the grant -- the PKCS#11 session, the
 *              login state, the object handles, the facade process -- and the operations
 *              performed on it.
 *
 *  So: a grant exists in the frontend before the backend has a session, and can outlive
 *  a backend restart only by dying, loudly, with reason "backend_gone". The backend
 *  cannot expire a grant, cannot renew one, and cannot tell which application owns it;
 *  it can only report that the hardware behind one has gone away.
 *
 *  A grant authorises ONE certificate, ONE key, ONE operation set, ONE verified caller,
 *  for ONE bounded time. It is not a bearer capability: the session handle names a
 *  grant, and possession of the path without the owning connection grants nothing.
 *
 *  LIFETIME IS NOT SIMPLY THE OWNER'S D-BUS CONNECTION, and getting this wrong breaks in
 *  both directions. The process that actually performs the cryptography may be a
 *  BROWSER'S NETWORK SUBPROCESS with its own connection to the endpoint. Killing the
 *  grant when the owner's D-Bus connection drops can terminate a valid handshake; keeping
 *  it alive for the subprocess permits use after the request that authorised it ended.
 *  So:
 *
 *    - ONE OWNER connection, which acquired the grant and is the only one that may
 *      release, renew, sign with or open an endpoint on it;
 *    - ZERO OR MORE DELEGATED ENDPOINT HOLDERS, connections the owner caused to exist;
 *    - the grant dies when the owner releases it, OR when all permitted holders have
 *      gone;
 *    - a SHORT ORPHAN GRACE PERIOD covers acquisition-to-connection, after which an
 *      unclaimed grant is destroyed;
 *    - expires_at always applies.
 *
 *  This is the one place the design deliberately departs from
 *  org.freedesktop.portal.Session's "a client vanishing closes its sessions", and the
 *  reason is written down rather than assumed.
 *
 *  MULTIPLE CONCURRENT GRANTS PER APPLICATION are supported and independent: separate
 *  lifetimes, separate cancellation, separate certificates, separate policy. Two origins
 *  in one browser is the normal case, not the exotic one.
 *
 *  The fd-lifetime rules of org.freedesktop.portal.Usb -- usable until released, until
 *  the connection closes, until the device is removed, or until the portal revokes them
 *  -- are the precedent and are deliberately mirrored.
 *
 *  SELECTION MEMORY IS NOT AUTHORISATION, and it does not live here: it lives in the
 *  permission store (permission-store.h), where the desktop's own UI can list and revoke
 *  it. Three things must never be conflated: remembering WHICH CERTIFICATE was selected
 *  (the only one offered); TOKEN LOGIN CACHING (hardware behaviour nobody here controls
 *  and must not present as a feature); and REMEMBERED AUTHORISATION TO USE THE KEY
 *  (deliberately absent). There is no "remember PIN".
 *
 *  Sketch only; nothing here is implemented.
 */

typedef enum
{
	SMARTCARD_INVALIDATED_RELEASED,
	SMARTCARD_INVALIDATED_EXPIRED,
	SMARTCARD_INVALIDATED_TOKEN_REMOVED,
	SMARTCARD_INVALIDATED_OWNER_GONE,
	SMARTCARD_INVALIDATED_POLICY,
	SMARTCARD_INVALIDATED_SERVICE_SHUTDOWN,
	SMARTCARD_INVALIDATED_BACKEND_GONE, /**< new with the split: the backend died, so the
	                                         token session behind this grant is gone */
	SMARTCARD_INVALIDATED_ERROR
} SmartcardInvalidationReason;

typedef struct
{
	char* grant_id;      /**< opaque, for logs and GrantInvalidated. Not a capability. */
	char* session_handle; /**< the object path; the handle callers actually use */
	char* owner_unique_name;
	SmartcardAppInfo* app_info; /**< resolved by the frontend, sent to the backend, and
	                                 displayed by it with its honesty level */
	SmartcardPurpose purpose;
	gboolean may_sign;
	gboolean may_decrypt;
	char** allowed_mechanisms; /**< the frontend's allow-list intersected with what the
	                                backend reported the key can do */
	GByteArray* certificate_der;
	GPtrArray* chain_der;
	char* chain_status;   /**< "complete" | "partial" | "leaf_only". COMPLETENESS, NOT TRUST. */
	GVariant* token_display; /**< DISPLAY identity only, as the backend reported it. The
	                              frontend never learns a card serial it could log. */
	char* certificate_id; /**< stable id for selection memory; the key the permission
	                           store entry holds, if the user accepted one */
	gint64 expires_at;
	guint operations_used;
	guint operation_limit; /**< 0 = unlimited within the lifetime; 1 = single-use */
	guint endpoint_holders;
	gboolean terminal; /**< one atomic terminal state; a dead grant never revives */
	SmartcardInvalidationReason invalidation_reason;
} SmartcardGrant;

typedef struct SmartcardRegistry SmartcardRegistry;

/** Create a grant from the backend's AcquireCredential results, INTERSECTED with what
 *  the frontend will allow. Applies the per-caller and global concurrent grant caps, and
 *  the lifetime ceiling: requested_lifetime is a CEILING REQUEST, not a floor, policy may
 *  grant less and never grants more -- and a backend that returns a longer one gets it
 *  clamped and logged, not honoured. */
SmartcardGrant* smartcard_registry_create(SmartcardRegistry* registry,
                                          const char* session_handle,
                                          const SmartcardAppInfo* app_info,
                                          SmartcardPurpose purpose, guint32 requested_lifetime,
                                          GVariant* impl_results, GError** error);

/** Look up a grant, checking that @unique_name is entitled to act on it. Only the OWNER
 *  may release or renew; a delegated holder may only use the endpoint. */
SmartcardGrant* smartcard_registry_lookup(SmartcardRegistry* registry, const char* session_handle,
                                          const char* unique_name, GError** error);

/** Extend a grant. ONLY while the caller identity and token binding are unchanged, and
 *  NEVER expanding permitted operations or mechanisms. Reauthorisation is required after
 *  long inactivity, token removal and reinsertion, a policy change, or a change in
 *  application identity. Enforced entirely in the frontend; the backend is not asked. */
gboolean smartcard_registry_renew(SmartcardRegistry* registry, SmartcardGrant* grant,
                                  guint32 requested_lifetime, GError** error);

/** Terminate a grant: close the frontend session, close the backend's (which closes
 *  sessions, logs out where the token permits, poisons every endpoint and cancels
 *  in-flight operations), emit GrantInvalidated and Session.Closed. Idempotent --
 *  releasing an already-dead grant succeeds. */
void smartcard_registry_invalidate(SmartcardRegistry* registry, SmartcardGrant* grant,
                                   SmartcardInvalidationReason reason);

/** The backend reported that the hardware behind a grant is gone (SessionInvalidated).
 *  Card removal invalidates immediately; the endpoint is poisoned rather than left to
 *  rebind to a card inserted later. */
void smartcard_registry_impl_invalidated(SmartcardRegistry* registry, const char* session_handle,
                                         const char* reason);

/** Owner connection vanished. Starts the orphan grace period rather than killing the
 *  grant outright, because a delegated subprocess may still be mid-handshake. */
void smartcard_registry_owner_gone(SmartcardRegistry* registry, const char* unique_name);

/** The backend vanished from the bus. Every grant dies with SMARTCARD_INVALIDATED_
 *  BACKEND_GONE: there is no reconnecting to a PKCS#11 session in a process that no
 *  longer exists, and pretending otherwise would leave callers holding handles to
 *  nothing. */
void smartcard_registry_backend_gone(SmartcardRegistry* registry);

#endif /* SMARTCARD_FRONTEND_GRANT_REGISTRY_H */
