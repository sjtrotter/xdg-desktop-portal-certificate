/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef XCC_UI_H
#define XCC_UI_H
#include "core.h"

#ifdef __cplusplus
extern "C"
{
#endif
	typedef uint64_t XccUiId;

	typedef enum
	{
		XCC_VALIDITY_VALID,
		XCC_VALIDITY_EXPIRED,
		XCC_VALIDITY_NOT_YET_VALID,
		XCC_VALIDITY_UNKNOWN
	} XccValidity;

	/* Distinguish SDK placeholders from literal external display text. */
#define XCC_DISPLAY_SUBJECT_FALLBACK (1u << 0)
#define XCC_DISPLAY_ISSUER_FALLBACK (1u << 1)
#define XCC_DISPLAY_TOKEN_FALLBACK (1u << 2)
#define XCC_DISPLAY_CALLER_FALLBACK (1u << 3)

	typedef struct
	{
		uint32_t struct_size, abi_version;
		uint64_t id;
		const char* subject;
		const char* issuer;
		const char* token;
		const char* reader;
		const char* expiry;
		const char* detail;
		const char* fingerprint;
		bool invalid;
		/* Unix seconds; nonpositive dates are unknown. Validity uses the core's clock. */
		XCC_ALIGNAS(8) int64_t not_before;
		int64_t not_after;
		uint32_t validity; /* XccValidity */
		const char* key_type; /* Algorithm identifier, NULL when unknown. */
		uint32_t key_size;
		uint32_t display_flags;
	} XccChooserCandidateView;

	/* Immutable and borrowed during callbacks; external display fields are sanitized in core. */
	typedef struct
	{
		uint32_t struct_size, abi_version;
		uint64_t revision;
		const XccChooserCandidateView* candidates;
		size_t n_candidates;
		const char* caller_name;
		const char* app_id;
		XccIdentityLevel identity_level;
		const char* identity_detail;
		XccPurpose purpose;
		const char* purpose_text;
		const char* purpose_detail;
		bool may_sign;
		bool may_decrypt;
		const char* operation_scope;
		uint32_t lifetime_seconds;
		const char* duration;
		const char* later_prompt;
		const char* reason_label;
		const char* untrusted_reason;
		bool tokens_present;
		const char* parent_window;
		const char* activation_token;
		XCC_ALIGNAS(8) bool generic_purpose; /* Generic disclosure; purpose still governs permissions. */
		uint32_t display_flags;
	} XccChooserView;

	/* Original padded sizeof: round the last original member's end to the
	 * original alignment (before XCC_ALIGNAS on the appended members). */
#define XCC_CHOOSER_CANDIDATE_VIEW_V1_SIZE \
	XCC_PADDED_SIZE(offsetof(XccChooserCandidateView, invalid) + sizeof(bool), XCC_MAX_ALIGNOF(uint64_t, const char*))
#define XCC_CHOOSER_VIEW_V1_SIZE \
	XCC_PADDED_SIZE(offsetof(XccChooserView, activation_token) + sizeof(const char*), XCC_MAX_ALIGNOF(uint64_t, const char*))

	/* Rows have a uniform byte stride supplied by the producer, allowing fields to
	 * be appended without changing how an older UI walks the candidate array. */
	static inline const XccChooserCandidateView* xcc_chooser_view_candidate(
		const XccChooserView* view, size_t index)
	{
		if (view == NULL || view->struct_size < XCC_CHOOSER_VIEW_V1_SIZE ||
			view->abi_version != XCC_ABI_VERSION || index >= view->n_candidates ||
			view->candidates == NULL)
			return NULL;
		size_t stride = view->candidates->struct_size;
		if (stride < XCC_CHOOSER_CANDIDATE_VIEW_V1_SIZE ||
			view->candidates->abi_version != XCC_ABI_VERSION ||
			index > (SIZE_MAX - XCC_CHOOSER_CANDIDATE_VIEW_V1_SIZE) / stride)
			return NULL;
		return (const XccChooserCandidateView*)((const uint8_t*)view->candidates + index * stride);
	}

	typedef enum
	{
		XCC_PIN_STATUS_NONE, /* Busy-only update / initial presentation. */
		XCC_PIN_STATUS_INCORRECT,
		XCC_PIN_STATUS_REQUIRED,
		XCC_PIN_STATUS_TOO_LONG,
		XCC_PIN_STATUS_MEMORY_UNAVAILABLE
	} XccPinStatus;

	/* Borrowed during show/update. Retry flags come only from the token. */
	typedef struct
	{
		uint32_t struct_size, abi_version;
		const char* token_label;
		const char* reader;
		const char* caller_display;
		const char* purpose_display;
		const char* parent_window;
		/* USER or CONTEXT_SPECIFIC; no provider/session handles cross the UI boundary. */
		bool context_specific;
		bool protected_path;
		bool busy;
		bool count_low;
		bool final_try;
		bool locked;
		/* NULL updates busy state; non-NULL requests fresh input. */
		const char* status;
		XCC_ALIGNAS(8) uint32_t purpose; /* XccPurpose, ignored when generic_purpose is true. */
		bool generic_purpose;
		uint32_t status_code; /* XccPinStatus; non-NONE requests fresh input. */
		uint32_t display_flags;
	} XccPinView;
#define XCC_PIN_VIEW_V1_SIZE \
	XCC_PADDED_SIZE(offsetof(XccPinView, status) + sizeof(const char*), XCC_MAX_ALIGNOF(uint32_t, const char*))

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
XCC_API void xcc_choose(XccContext*, XccUiId, uint64_t revision, uint64_t candidate_id);
/* Acknowledge once the provider can receive warnings; stale/duplicate IDs are ignored. */
XCC_API void xcc_pin_ready(XccContext*, XccUiId);
XCC_API void xcc_pin_submit(XccContext*, XccUiId, XccSecret*); /* consumes, even for stale IDs */
XCC_API void xcc_warning_reply(XccContext*, XccUiId, uint64_t warning_id, bool accepted);
XCC_API void xcc_ui_cancel(XccContext*, XccUiId);
XCC_API void xcc_ui_failed(XccContext*, XccUiId, XccErrorCode);
#ifdef __cplusplus
}
#endif

#endif
