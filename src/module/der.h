/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */
#ifndef PKCS11_PORTAL_DER_H
#define PKCS11_PORTAL_DER_H

#include <glib.h>

/** Accept only definite, minimal DER lengths within the input buffer. */

#define PORTAL_DER_INTEGER 0x02
#define PORTAL_DER_BIT_STRING 0x03
#define PORTAL_DER_OCTET_STRING 0x04
#define PORTAL_DER_NULL 0x05
#define PORTAL_DER_OID 0x06
#define PORTAL_DER_SEQUENCE 0x30

typedef struct
{
	guint8 tag;
	const guint8* value;
	gsize length;
	gsize consumed; /**< Includes tag and length bytes. */
} PortalDerTlv;

gboolean portal_der_read(const guint8* data, gsize size, PortalDerTlv* out);

gboolean portal_der_read_tag(const guint8* data, gsize size, guint8 tag, PortalDerTlv* out);

GBytes* portal_der_encode(guint8 tag, const guint8* value, gsize size);

#endif
