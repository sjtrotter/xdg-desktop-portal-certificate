/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */
#ifndef CERTIFICATE_TEST_FAKE_CHOOSER_PROVIDER_H
#define CERTIFICATE_TEST_FAKE_CHOOSER_PROVIDER_H

#include "ui/chooser-provider.h"

typedef struct
{
	CertificateChooserProvider provider;
	XccUiId id;
	XccChooserView view;
	XccChooserCandidateView* candidates;
	GPtrArray* text;
	guint shows;
	guint updates;
	guint closes;
	gboolean cancel_on_show;
} FakeChooserProvider;

void fake_chooser_provider_init(FakeChooserProvider* fake);
void fake_chooser_provider_clear(FakeChooserProvider* fake);
void fake_chooser_provider_choose(FakeChooserProvider* fake, gsize index);
void fake_chooser_provider_cancel(FakeChooserProvider* fake);

#endif
