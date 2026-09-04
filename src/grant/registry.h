/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SMARTCARD_GRANT_REGISTRY_H
#define SMARTCARD_GRANT_REGISTRY_H

#include <glib.h>

#include "../dbus/service.h"
#include "../ui/chooser.h"

/** @file
 *  Live grants: what was authorised, by whom, for how long, and when it dies.
 *
 *  A grant authorises ONE certificate, ONE key, ONE operation set, ONE verified caller,
 *  for ONE bounded time. It is not a capability that can be passed around: grant_id
 *  names a grant, and possession of the id without the owning connection grants nothing.
 *
 *  LIFETIME IS NOT SIMPLY THE OWNER'S D-BUS CONNECTION, and getting this wrong breaks in
 *  both directions. The process that actually performs the cryptography may be a
 *  BROWSER'S NETWORK SUBPROCESS with its own connection to the endpoint. Killing the
 *  grant when the owner's D-Bus connection drops can terminate a valid handshake; keeping
 *  it alive for the subprocess permits use after the request that authorised it ended.
 *  So:
 *
 *    - ONE OWNER connection, which acquired the grant and is the only one that may
 *      release it;
 *    - ZERO OR MORE DELEGATED ENDPOINT HOLDERS, connections the owner caused to exist;
 *    - the grant dies when the owner releases it, OR when all permitted holders have
 *      gone;
 *    - a SHORT ORPHAN GRACE PERIOD covers acquisition-to-connection, after which an
 *      unclaimed grant is destroyed;
 *    - expires_at always applies.
 *
 *  MULTIPLE CONCURRENT GRANTS PER APPLICATION are supported and independent: separate
 *  lifetimes, separate cancellation, separate certificates, separate policy. Two origins
 *  in one browser is the normal case, not the exotic one.
 *
 *  The fd-lifetime rules of org.freedesktop.portal.Usb -- usable until released, until
 *  the connection closes, until the device is removed, or until the portal revokes them
 *  -- are the precedent and are deliberately mirrored.
 *
 *  SELECTION MEMORY IS NOT AUTHORISATION. Three things must never be conflated:
 *  remembering WHICH CERTIFICATE was selected (the only one offered here); TOKEN LOGIN
 *  CACHING (hardware behaviour this service does not control and must not present as a
 *  feature); and REMEMBERED AUTHORISATION TO USE THE KEY (deliberately absent). Selection
 *  memory preselects; it never skips the trusted consent step, never skips a PIN prompt,
 *  is unavailable to unverified callers, is session-scoped unless made durable, and is
 *  listed and revocable in this service's own UI. There is no "remember PIN".
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
	SMARTCARD_INVALIDATED_ERROR
} SmartcardInvalidationReason;

typedef struct
{
	char* grant_id;
	char* owner_unique_name;
	SmartcardCallerIdentity* caller;
	SmartcardPurpose purpose;
	gboolean may_sign;
	gboolean may_decrypt;
	char** allowed_mechanisms;
	GByteArray* certificate_der;
	GPtrArray* chain_der;
	char* chain_status;   /**< "complete" | "partial" | "leaf_only". COMPLETENESS, NOT TRUST. */
	SmartcardToken* token; /**< identified by every stable attribute, never by slot number */
	gint64 expires_at;
	guint operations_used;
	guint operation_limit; /**< 0 = unlimited within the lifetime; 1 = single-use */
	guint endpoint_holders;
	gboolean terminal; /**< one atomic terminal state; a dead grant never revives */
	SmartcardInvalidationReason invalidation_reason;
} SmartcardGrant;

typedef struct SmartcardRegistry SmartcardRegistry;

/** Create a grant from a chooser result. Applies the per-caller and global concurrent
 *  grant caps, and the lifetime ceiling: requested_lifetime is a CEILING REQUEST, not a
 *  floor, and policy may grant less and never grants more. */
SmartcardGrant* smartcard_registry_create(SmartcardRegistry* registry,
                                          const SmartcardChooserResult* choice,
                                          const SmartcardCallerIdentity* caller,
                                          SmartcardPurpose purpose, guint32 requested_lifetime,
                                          GError** error);

/** Look up a grant, checking that @unique_name is entitled to act on it. Only the OWNER
 *  may release or renew; a delegated holder may only use the endpoint. */
SmartcardGrant* smartcard_registry_lookup(SmartcardRegistry* registry, const char* grant_id,
                                          const char* unique_name, GError** error);

/** Extend a grant. ONLY while the caller identity and token binding are unchanged, and
 *  NEVER expanding permitted operations or mechanisms. Reauthorisation is required after
 *  long inactivity, token removal and reinsertion, a policy change, or a change in
 *  application identity. */
gboolean smartcard_registry_renew(SmartcardRegistry* registry, SmartcardGrant* grant,
                                  guint32 requested_lifetime, GError** error);

/** Terminate a grant: close sessions, log out where the token permits, poison every
 *  endpoint, cancel in-flight operations, emit GrantInvalidated. Idempotent -- releasing
 *  an already-dead grant succeeds. */
void smartcard_registry_invalidate(SmartcardRegistry* registry, SmartcardGrant* grant,
                                   SmartcardInvalidationReason reason);

/** Every grant bound to a token that has just left. Card removal invalidates
 *  immediately; the endpoint is poisoned rather than left to rebind. */
void smartcard_registry_token_removed(SmartcardRegistry* registry, const SmartcardToken* token);

/** Owner connection vanished. Starts the orphan grace period rather than killing the
 *  grant outright, because a delegated subprocess may still be mid-handshake. */
void smartcard_registry_owner_gone(SmartcardRegistry* registry, const char* unique_name);

#endif /* SMARTCARD_GRANT_REGISTRY_H */
