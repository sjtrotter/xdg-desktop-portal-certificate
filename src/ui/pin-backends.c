/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#include "pin-backends.h"

static const CertificatePinProvider* selected_provider;

gboolean certificate_pin_set_prompt_kind(const char* name, GError** error)
{
	const CertificatePinProvider* provider = NULL;

	if (name == NULL || g_ascii_strcasecmp(name, "auto") == 0)
	{
#if HAVE_GCR
		if (certificate_pin_provider_system_available())
			provider = certificate_pin_provider_system();
#endif
		if (provider == NULL)
			provider = certificate_pin_provider_gtk();
	}
	else if (g_ascii_strcasecmp(name, "gtk") == 0)
		provider = certificate_pin_provider_gtk();
	else if (g_ascii_strcasecmp(name, "system") == 0)
	{
#if HAVE_GCR
		provider = certificate_pin_provider_system();
#else
		provider = certificate_pin_provider_gtk();
#endif
	}
	else
	{
		g_set_error(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
		            "Unknown PIN prompt '%s'; expected auto, gtk or system", name);
		return FALSE;
	}

	selected_provider = provider;
	certificate_pin_set_provider(provider);
	g_message("pin-prompt-selected detail=%s", provider->name);
	return TRUE;
}

const char* certificate_pin_prompt_name(void)
{
	return selected_provider != NULL ? selected_provider->name : "gtk";
}
