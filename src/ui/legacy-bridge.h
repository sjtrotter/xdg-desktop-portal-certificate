/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef CERTIFICATE_LEGACY_BRIDGE_H
#define CERTIFICATE_LEGACY_BRIDGE_H
#include "../core/ui.h"
#include "chooser-provider.h"
#include "pin-provider.h"
const XccUiV1* certificate_ui_bridge_table(void);
void certificate_ui_bridge_attach(XccContext*);
#endif
