/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef XCC_CORE_H
#define XCC_CORE_H
#include <stdbool.h>
#include <stddef.h>
#include "abi.h"
#include "session.h"
#include "secret.h"

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct XccContext XccContext;
	typedef struct XccRequest XccRequest;
	typedef struct XccCandidate XccCandidate;
	typedef struct XccUiV1 XccUiV1;

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
	} XccCandidateInfo;
	typedef struct
	{
		uint32_t struct_size, abi_version;
		uint64_t owner_generation;
		const char* app_id;
		CertificateIdentityLevel identity_level;
		bool identity_present;
		const char* log_id;
	} XccSessionSpec;
	typedef struct
	{
		uint64_t owner_generation;
		const char* app_id;
		CertificateIdentityLevel identity_level;
		bool identity_present;
	} XccPrincipal;

	typedef struct
	{
		uint32_t struct_size, abi_version;
		XccPrincipal principal;
		CertificatePurpose purpose;
		bool generic_purpose_present, generic_purpose;
		const char* parent_window;
		const char* activation_token;
		const char* reason;
		bool lifetime_present;
		uint32_t lifetime_seconds;
		bool sign_present, sign;
		bool interaction_present, interaction_forbidden;
		bool issuers_present;
		const XccBytes* issuers;
		size_t n_issuers;
		bool key_usage_present, eku_oids_present, key_algorithms_present;
		const char* const* key_usage;
		const char* const* eku_oids;
		const char* const* key_algorithms;
		bool token_label_present, piv_slot_present;
		const char* token_label;
		const char* piv_slot;
	} XccAcquireSpec;
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
		/* Transitional injection: borrowed until shutdown completion. */
		CertificateTokens* tokens;
	} XccConfig;

	/* One active context; constructors copy their inputs before returning. UI may be NULL
	 * only to compose the registered standalone providers. Receiver lives through shutdown. */
	XccContext* xcc_context_new(const XccConfig*, const XccUiV1*, const XccDispatch*, XccError*);
	XccContext* xcc_context_ref(XccContext*);
	void xcc_context_unref(XccContext*);
	XccSession* xcc_session_new(XccContext*, const XccSessionSpec*, XccError*);
	/* Caller owns a request reference. Result fields are borrowed during exactly one done
	 * callback on the dispatcher; retain candidates explicitly for a longer lifetime. */
	XccRequest* xcc_acquire_async(XccSession*, const XccAcquireSpec*, XccDone, void*);
	XccRequest* xcc_sign_async(XccSession*, const XccSignSpec*, XccDone, void*);
	XccRequest* xcc_get_capabilities_async(XccContext*, XccDone, void*);
	XccRequest* xcc_request_ref(XccRequest*);
	void xcc_request_unref(XccRequest*);
	void xcc_request_cancel(XccRequest*, XccCancelReason);
	/* Call once; completion follows workers, UI deliveries and retained provider callbacks. */
	void xcc_context_shutdown_async(XccContext*, XccShutdownDone, void*);
	/* The adapter advances this after authorizing a new frontend owner. */
	void xcc_context_set_owner_generation(XccContext*, uint64_t);
	const char* xcc_error_wire_name(XccErrorCode);
	uint32_t xcc_error_wire_response(XccErrorCode);
	XccCandidate* xcc_candidate_ref(const XccCandidate*);
	void xcc_candidate_unref(XccCandidate*);
	XccBytes xcc_candidate_certificate(const XccCandidate*);
	const XccCandidateInfo* xcc_candidate_info(const XccCandidate*);
	/* Internal serialization accessor; never exported as SDK. */
	const CertificateCandidate* xcc_candidate_internal(const XccCandidate*);
#ifdef __cplusplus
}
#endif
#endif
