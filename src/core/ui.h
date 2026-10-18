/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef XCC_UI_H
#define XCC_UI_H
#include "core.h"
#include "../ui/chooser-provider.h"
#include "../ui/pin-provider.h"

G_BEGIN_DECLS
typedef enum
{
	XCC_WARNING_FINAL_TRY
} XccWarningCode;
typedef struct
{
	uint32_t struct_size, abi_version;
	XccWarningCode code;
	uint64_t warning_id;
	const char* message;
} XccWarning;
#define XCC_UI_CHOOSER_NEEDS_DISPLAY 1u
#define XCC_UI_PIN_NEEDS_DISPLAY 2u
#define XCC_UI_NEEDS_DISPLAY (XCC_UI_CHOOSER_NEEDS_DISPLAY | XCC_UI_PIN_NEEDS_DISPLAY)
struct XccUiV1
{
	uint32_t struct_size, abi_version, capabilities;
	void* user;
	void (*chooser_show)(void*, XccUiId, const XccChooserView*);
	void (*chooser_update)(void*, XccUiId, const XccChooserView*);
	/* Call xcc_pin_ready() once presentation can receive warnings, including typed PINs. */
	void (*pin_show)(void*, XccUiId, const XccPinView*);
	void (*pin_update)(void*, XccUiId, const XccPinView*);
	void (*warning)(void*, XccUiId, const XccWarning*);
	void (*hide)(void*, XccUiId);
	void (*close)(void*, XccUiId);
};
void xcc_choose(XccContext*, XccUiId, uint64_t revision, uint64_t candidate_id);
/* Acknowledge once the provider can receive warnings; stale/duplicate IDs are ignored. */
void xcc_pin_ready(XccContext*, XccUiId);
void xcc_pin_submit(XccContext*, XccUiId, XccSecret*); /* consumes, even for stale IDs */
void xcc_warning_reply(XccContext*, XccUiId, uint64_t warning_id, bool accepted);
void xcc_ui_cancel(XccContext*, XccUiId);
void xcc_ui_failed(XccContext*, XccUiId, XccErrorCode);
G_END_DECLS

#endif
