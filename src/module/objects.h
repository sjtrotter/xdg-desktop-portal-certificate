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

/** What a C_FindObjectsInit template can be taken to mean. */
typedef enum
{
	/** A search this token could never answer, or one whose answer is about
	 *  some other certificate: an issuer, subject or serial lookup, a trust
	 *  category, a data object, a label naming something else. It gets no
	 *  objects while there is no grant, and it never acquires one. */
	PORTAL_TEMPLATE_UNRELATED = 0,

	/** "List what is on this token": an empty template, or a class on its own.
	 *  It acquires only when PKCS11_PORTAL_CERTIFICATE_ENUMERATE says so. */
	PORTAL_TEMPLATE_ENUMERATES,

	/** A search that can only mean "give me the client credential": the object
	 *  label of the shared contract, a CKA_ID, or the private key. */
	PORTAL_TEMPLATE_NAMES_CREDENTIAL
} PortalTemplateIntent;

/** Which of the three @templ is. Reads no environment; the gate below does. */
PortalTemplateIntent portal_template_intent(CK_ATTRIBUTE_PTR templ, CK_ULONG count);

/** Whether a search for @templ may acquire a credential, which is the same
 *  question as whether it may put a chooser on the user's screen. A search for
 *  anything else must never provoke one. */
gboolean portal_template_wants_credential(CK_ATTRIBUTE_PTR templ, CK_ULONG count);

/** A stable fingerprint of @templ, ignoring CKA_CLASS, for the refusal memory:
 *  the certificate search and the key search of one handshake differ only in
 *  their class and must count as the same search. */
guint portal_template_fingerprint(CK_ATTRIBUTE_PTR templ, CK_ULONG count);

#endif /* PKCS11_PORTAL_OBJECTS_H */
