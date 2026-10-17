/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

#ifndef CERTIFICATE_UI_CHOOSER_H
#define CERTIFICATE_UI_CHOOSER_H

#include "chooser-provider.h"

const CertificateChooserProvider* certificate_chooser_provider_gtk(void);

/* Main-thread test hook observes announcements after the window maps. */
typedef void (*CertificateChooserAnnounceHook)(const char* text, gpointer user_data);
void certificate_chooser_set_announce_hook(CertificateChooserAnnounceHook hook, gpointer user_data);

#endif
