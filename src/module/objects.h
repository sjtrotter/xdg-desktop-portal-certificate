/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef PKCS11_PORTAL_OBJECTS_H
#define PKCS11_PORTAL_OBJECTS_H

#include <glib.h>

#include <p11-kit/pkcs11.h>

#include "grant.h"

/** @file
 *  The three objects a grant becomes: the leaf certificate, its public key and
 *  its private key.
 *
 *  The intermediates in `chain_der` are deliberately not objects. A consumer
 *  asks for this token's certificate by URI -- `type=cert` and nothing more
 *  specific -- and an unambiguous answer is worth more than a chain the
 *  consumer can rebuild from its own stores.
 *
 *  The private key has no CKA_VALUE and never will; the attributes that would
 *  carry key material answer CKR_ATTRIBUTE_SENSITIVE. CKA_SENSITIVE is TRUE and
 *  CKA_EXTRACTABLE is FALSE, which is what the token behind the portal reports
 *  and what a caller must be told: a FALSE CKA_SENSITIVE would say the value can
 *  be read.
 */

typedef struct
{
	CK_ATTRIBUTE_TYPE type;
	GBytes* value;       /**< NULL when @sensitive */
	gboolean sensitive;
} PortalAttribute;

typedef struct
{
	CK_OBJECT_HANDLE handle;
	CK_OBJECT_CLASS object_class;
	GArray* attributes; /**< PortalAttribute */
} PortalObject;

typedef struct
{
	GPtrArray* objects; /**< PortalObject* */
} PortalObjects;

/** Build the objects for @grant. @generation is mixed into the handles so that
 *  a handle from a released grant is invalid rather than ambiguous. */
PortalObjects* portal_objects_new(const PortalGrant* grant, guint generation, GError** error);

void portal_objects_free(PortalObjects* objects);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PortalObjects, portal_objects_free)

PortalObject* portal_objects_lookup(PortalObjects* objects, CK_OBJECT_HANDLE handle);

/** Whether @object satisfies every attribute in @templ. */
gboolean portal_object_matches(const PortalObject* object, CK_ATTRIBUTE_PTR templ, CK_ULONG count);

/** The handles of every matching object, in table order. */
GArray* portal_objects_find(PortalObjects* objects, CK_ATTRIBUTE_PTR templ, CK_ULONG count);

/** C_GetAttributeValue's per-attribute protocol: size query, buffer too small,
 *  unavailable, sensitive. */
CK_RV portal_object_get_attributes(const PortalObject* object, CK_ATTRIBUTE_PTR templ,
                                   CK_ULONG count);

/** Whether a search for @templ could be satisfied by this token at all, i.e.
 *  whether it names a class this module has. A search for anything else must
 *  never provoke a chooser. */
gboolean portal_template_wants_credential(CK_ATTRIBUTE_PTR templ, CK_ULONG count);

/** A stable fingerprint of @templ, ignoring CKA_CLASS, for the refusal memory:
 *  the certificate search and the key search of one handshake differ only in
 *  their class and must count as the same search. */
guint portal_template_fingerprint(CK_ATTRIBUTE_PTR templ, CK_ULONG count);

#endif /* PKCS11_PORTAL_OBJECTS_H */
