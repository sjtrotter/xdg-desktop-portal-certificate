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

/** Expose only the leaf and its key pair; private-key material returns CKR_ATTRIBUTE_SENSITIVE. */

typedef struct
{
	CK_ATTRIBUTE_TYPE type;
	GBytes* value;       /**< NULL for sensitive attributes. */
	gboolean sensitive;
} PortalAttribute;

typedef struct
{
	CK_OBJECT_HANDLE handle;
	CK_OBJECT_CLASS object_class;
	GArray* attributes; /**< PortalAttribute elements. */
} PortalObject;

typedef struct
{
	GPtrArray* objects; /**< PortalObject* elements. */
} PortalObjects;

/** The generation prevents reuse of handles from released grants. */
PortalObjects* portal_objects_new(const PortalGrant* grant, guint generation, GError** error);

void portal_objects_free(PortalObjects* objects);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PortalObjects, portal_objects_free)

PortalObject* portal_objects_lookup(PortalObjects* objects, CK_OBJECT_HANDLE handle);

gboolean portal_object_matches(const PortalObject* object, CK_ATTRIBUTE_PTR templ, CK_ULONG count);

GArray* portal_objects_find(PortalObjects* objects, CK_ATTRIBUTE_PTR templ, CK_ULONG count);

CK_RV portal_object_get_attributes(const PortalObject* object, CK_ATTRIBUTE_PTR templ,
                                   CK_ULONG count);

typedef enum
{
	PORTAL_TEMPLATE_UNRELATED = 0,

	/** Class-only and empty searches acquire only when PKCS11_PORTAL_CERTIFICATE_ENUMERATE is enabled. */
	PORTAL_TEMPLATE_ENUMERATES,

	PORTAL_TEMPLATE_NAMES_CREDENTIAL
} PortalTemplateIntent;

PortalTemplateIntent portal_template_intent(CK_ATTRIBUTE_PTR templ, CK_ULONG count);

gboolean portal_template_wants_credential(CK_ATTRIBUTE_PTR templ, CK_ULONG count);

/** Ignore CKA_CLASS so certificate and key searches share refusal memory. */
guint portal_template_fingerprint(CK_ATTRIBUTE_PTR templ, CK_ULONG count);

#endif
