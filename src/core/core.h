/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef XCC_CORE_H
#define XCC_CORE_H
#include <stdbool.h>
#include <stddef.h>
#include "abi.h"
#include "secret.h"

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct XccContext XccContext;
	typedef struct _XccSession XccSession;
	typedef struct XccRequest XccRequest;
	typedef struct XccCandidate XccCandidate;
	typedef struct XccUiV1 XccUiV1;

	typedef enum
	{
		XCC_PURPOSE_CLIENT_AUTH,
		XCC_PURPOSE_SIGNING,
		XCC_PURPOSE_EMAIL,
		XCC_PURPOSE_SSH
	} XccPurpose;
	typedef enum
	{
		XCC_IDENTITY_VERIFIED_SANDBOXED,
		XCC_IDENTITY_DERIVED_HOST,
		XCC_IDENTITY_UNKNOWN
	} XccIdentityLevel;
	typedef enum
	{
		XCC_OK,
		XCC_ERROR_CANCELLED,
		XCC_ERROR_OWNER_GONE,
		XCC_ERROR_BACKEND_GONE,
		XCC_ERROR_NO_SUCH_SESSION,
		XCC_ERROR_INVALID_REQUEST,
		XCC_ERROR_INVALID_PURPOSE,
		XCC_ERROR_INVALID_FILTER,
		XCC_ERROR_DEVICE,
		XCC_ERROR_INTERACTION_REQUIRED,
		XCC_ERROR_NO_DISPLAY,
		XCC_ERROR_PIN_LOCKED,
		XCC_ERROR_TOKEN_REMOVED,
		XCC_ERROR_PIN_INCORRECT,
		XCC_ERROR_LOGIN_TIMEOUT,
		XCC_ERROR_NOT_SUPPORTED
	} XccErrorCode;
	typedef struct
	{
		uint32_t struct_size, abi_version;
		XccErrorCode code;
	} XccError;
	typedef enum
	{
		XCC_CANCEL_USER,
		XCC_CANCEL_OWNER_GONE,
		XCC_CANCEL_SESSION_CLOSED,
		XCC_CANCEL_BACKEND_GONE,
		XCC_CANCEL_TOKEN_REMOVED,
		XCC_CANCEL_DEVICE
	} XccCancelReason;
	typedef void (*XccFunction)(void*);
	typedef struct
	{
		uint32_t struct_size, abi_version;
		void* user;
		/* Always enqueue, including when called on the receiver thread. FIFO. */
		void (*post)(void* user, XccFunction function, void* closure);
	} XccDispatch;

	typedef struct
	{
		uint32_t struct_size, abi_version;
		const uint8_t* data;
		size_t size;
	} XccBytes;
	typedef struct
	{
		uint32_t struct_size, abi_version;
		XccBytes certificate;
		const char* subject;
		const char* issuer;
		const char* token;
		const char* reader;
		const char* key_type;
		const char* key_curve;
		uint32_t key_size;
		bool key_curve_present;
		const char* const* mechanisms;
		int64_t not_before, not_after;
		bool protected_path;
		/* Original wire metadata, not sanitized display text. Never NULL; no serial.
		 * Gate this extension through token_reader on struct_size. */
		XCC_ALIGNAS(8) const char* token_label;
		const char* token_manufacturer;
		const char* token_model;
		const char* token_reader;
	} XccCandidateInfo;
	typedef struct
	{
		uint32_t struct_size, abi_version;
		uint64_t owner_generation;
		const char* app_id;
		XccIdentityLevel identity_level;
		bool identity_present;
		const char* log_id;
	} XccSessionSpec;
	typedef struct
	{
		uint32_t struct_size, abi_version;
		uint64_t owner_generation;
		const char* app_id;
		XccIdentityLevel identity_level;
		bool identity_present;
	} XccPrincipal;

	typedef struct
	{
		uint32_t struct_size, abi_version;
		XccPrincipal principal;
		XccPurpose purpose;
		bool generic_purpose_present, generic_purpose;
		const char* parent_window;
		const char* activation_token;
		const char* reason;
		bool lifetime_present;
		uint32_t lifetime_seconds;
		bool sign_present, sign;
		bool interaction_present, interaction_forbidden;
		bool issuers_present;
		const XccBytes* issuers; /* Uniform stride from the first row's struct_size. */
		size_t n_issuers;
		bool key_usage_present, eku_oids_present, key_algorithms_present;
		const char* const* key_usage;
		const char* const* eku_oids;
		const char* const* key_algorithms;
		bool token_label_present, piv_slot_present;
		const char* token_label;
		const char* piv_slot;
	} XccAcquireSpec;
	/* Uniform producer stride permits larger rows. The producer owns the backing
	 * allocation; a malformed size/version/offset returns NULL. */
	static inline const XccBytes* xcc_acquire_spec_issuer(const XccAcquireSpec* spec, size_t index)
	{
		if (spec == NULL || spec->struct_size < sizeof(*spec) ||
			spec->abi_version != XCC_ABI_VERSION || spec->issuers == NULL ||
			index >= spec->n_issuers)
			return NULL;
		size_t stride = spec->issuers->struct_size;
		if (stride < sizeof(XccBytes) || spec->issuers->abi_version != XCC_ABI_VERSION ||
			index > (SIZE_MAX - sizeof(XccBytes)) / stride)
			return NULL;
		return (const XccBytes*)((const uint8_t*)spec->issuers + index * stride);
	}

	typedef struct
	{
		uint32_t struct_size, abi_version;
		XccPrincipal principal;
		const char* parent_window;
		const char* operation_id;
		const char* mechanism;
		XccBytes data;
		bool hash_present, mgf_present, salt_length_present, encoding_present;
		const char* hash;
		const char* mgf;
		uint32_t salt_length;
		const char* signature_encoding;
	} XccSignSpec;
	typedef enum
	{
		XCC_RESULT_ACQUIRE,
		XCC_RESULT_SIGN,
		XCC_RESULT_CAPABILITIES
	} XccResultKind;
	typedef struct
	{
		uint32_t struct_size, abi_version;
		XccResultKind kind;
		XccErrorCode error;
		bool candidate_present, signature_present, mechanisms_present;
		const XccCandidate* candidate;
		bool may_sign;
		XccBytes signature;
		const char* const* mechanisms;
		bool protected_path, has_display;
	} XccResult;
	typedef void (*XccDone)(XccRequest*, const XccResult*, void*);
	typedef void (*XccShutdownDone)(XccContext*, void*);
	typedef struct
	{
		uint32_t struct_size, abi_version;
		const char* const* module_paths;
		bool allow_software, has_display;
		void (*session_invalidated)(XccSession*, const char*, void*);
		void* user;
	} XccConfig;

	/* One active context; constructors copy inputs before returning.
	 * Supply a complete UI table; NULL is reserved for repository compatibility.
	 * The dispatcher receiver lives through shutdown. */
	XCC_API XccContext* xcc_context_new(const XccConfig*, const XccUiV1*, const XccDispatch*,
										XccError*);
	XCC_API XccContext* xcc_context_ref(XccContext*);
	XCC_API void xcc_context_unref(XccContext*);
	XCC_API XccSession* xcc_session_ref(XccSession*);
	XCC_API void xcc_session_unref(XccSession*);
	XCC_API void xcc_session_close(XccSession*);
	/* Retain asynchronous UI callbacks until they settle, including after close. */
	XCC_API void xcc_context_hold_ui(XccContext*);
	XCC_API void xcc_context_release_ui(XccContext*);
	XCC_API XccSession* xcc_session_new(XccContext*, const XccSessionSpec*, XccError*);
	/* Caller owns a request reference. Result fields are borrowed during exactly one done
	 * callback on the dispatcher; retain candidates explicitly for a longer lifetime. */
	XCC_API XccRequest* xcc_acquire_async(XccSession*, const XccAcquireSpec*, XccDone, void*);
	XCC_API XccRequest* xcc_sign_async(XccSession*, const XccSignSpec*, XccDone, void*);
	XCC_API XccRequest* xcc_get_capabilities_async(XccContext*, XccDone, void*);
	XCC_API XccRequest* xcc_request_ref(XccRequest*);
	XCC_API void xcc_request_unref(XccRequest*);
	XCC_API void xcc_request_cancel(XccRequest*, XccCancelReason);
	/* Call once; completion follows workers, UI deliveries and retained provider callbacks. */
	XCC_API void xcc_context_shutdown_async(XccContext*, XccShutdownDone, void*);
	/* The adapter advances this after authorizing a new frontend owner. */
	XCC_API void xcc_context_set_owner_generation(XccContext*, uint64_t);
	XCC_API const char* xcc_error_wire_name(XccErrorCode);
	XCC_API uint32_t xcc_error_wire_response(XccErrorCode);
	XCC_API XccCandidate* xcc_candidate_ref(const XccCandidate*);
	XCC_API void xcc_candidate_unref(XccCandidate*);
	XCC_API XccBytes xcc_candidate_certificate(const XccCandidate*);
	XCC_API const XccCandidateInfo* xcc_candidate_info(const XccCandidate*);
#ifdef __cplusplus
}
#endif
#endif
