/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "der.h"

#include <string.h>

gboolean portal_der_read(const guint8* data, gsize size, PortalDerTlv* out)
{
	gsize offset = 2;
	gsize length;

	g_return_val_if_fail(out != NULL, FALSE);

	if (data == NULL || size < 2)
		return FALSE;

	/* One-byte tags only: every structure this module reads uses them. */
	if ((data[0] & 0x1f) == 0x1f)
		return FALSE;

	if ((data[1] & 0x80) == 0)
	{
		length = data[1];
	}
	else
	{
		gsize count = data[1] & 0x7f;

		if (count == 0 || count > 4 || size < 2 + count)
			return FALSE;
		if (data[2] == 0)
			return FALSE;

		length = 0;
		for (gsize i = 0; i < count; i++)
			length = (length << 8) | data[2 + i];

		if (length < 0x80)
			return FALSE;

		offset = 2 + count;
	}

	if (length > size - offset)
		return FALSE;

	out->tag = data[0];
	out->value = data + offset;
	out->length = length;
	out->consumed = offset + length;
	return TRUE;
}

gboolean portal_der_read_tag(const guint8* data, gsize size, guint8 tag, PortalDerTlv* out)
{
	return portal_der_read(data, size, out) && out->tag == tag;
}

GBytes* portal_der_encode(guint8 tag, const guint8* value, gsize size)
{
	GByteArray* out = g_byte_array_new();

	g_byte_array_append(out, &tag, 1);

	if (size < 0x80)
	{
		guint8 byte = (guint8) size;

		g_byte_array_append(out, &byte, 1);
	}
	else
	{
		guint8 header[5];
		gsize count = 0;
		gsize remaining = size;

		while (remaining != 0)
		{
			count++;
			remaining >>= 8;
		}

		header[0] = (guint8) (0x80 | count);
		for (gsize i = 0; i < count; i++)
			header[1 + i] = (guint8) (size >> (8 * (count - 1 - i)));

		g_byte_array_append(out, header, (guint) (count + 1));
	}

	if (size > 0)
		g_byte_array_append(out, value, (guint) size);

	return g_byte_array_free_to_bytes(out);
}
