/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "core/ui.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK(condition)                                                                           \
	do                                                                                             \
	{                                                                                              \
		if (!(condition))                                                                          \
		{                                                                                          \
			fprintf(stderr, "line %d: %s\n", __LINE__, #condition);                                \
			return EXIT_FAILURE;                                                                   \
		}                                                                                          \
	} while (0)

int main(void)
{
	struct ExtendedRow
	{
		XccChooserCandidateView row;
		uint64_t future;
	} rows[2] = {0};
	for (size_t i = 0; i < 2; ++i)
	{
		rows[i].row.struct_size = sizeof(rows[i]);
		rows[i].row.abi_version = XCC_ABI_VERSION;
		rows[i].row.id = i + 1;
	}
	XccChooserView view = {.struct_size = sizeof(view),
						   .abi_version = XCC_ABI_VERSION,
						   .candidates = &rows[0].row,
						   .n_candidates = 2};
	CHECK(xcc_chooser_view_candidate(&view, 0) == &rows[0].row);
	CHECK(xcc_chooser_view_candidate(&view, 1) == &rows[1].row);
	CHECK(xcc_chooser_view_candidate(&view, 2) == NULL);
	CHECK(xcc_chooser_view_candidate(NULL, 0) == NULL);
	rows[0].row.struct_size = 0;
	CHECK(xcc_chooser_view_candidate(&view, 0) == NULL);
	rows[0].row.struct_size = XCC_CHOOSER_CANDIDATE_VIEW_V1_SIZE - 1;
	CHECK(xcc_chooser_view_candidate(&view, 1) == NULL);
	rows[0].row.struct_size = sizeof(rows[0]);
	rows[0].row.abi_version = XCC_ABI_VERSION + 1;
	CHECK(xcc_chooser_view_candidate(&view, 0) == NULL);
	rows[0].row.abi_version = XCC_ABI_VERSION;
	view.n_candidates = SIZE_MAX;
	CHECK(xcc_chooser_view_candidate(&view, SIZE_MAX / sizeof(rows[0]) + 1) == NULL);
	/* The product fits, but including the known row prefix would overflow. */
	rows[0].row.struct_size = UINT32_MAX;
	CHECK(xcc_chooser_view_candidate(&view, SIZE_MAX / UINT32_MAX) == NULL);
	rows[0].row.struct_size = sizeof(rows[0]);
	view.struct_size = XCC_CHOOSER_VIEW_V1_SIZE - 1;
	CHECK(xcc_chooser_view_candidate(&view, 0) == NULL);
	view.struct_size = sizeof(view);
	view.abi_version = XCC_ABI_VERSION + 1;
	CHECK(xcc_chooser_view_candidate(&view, 0) == NULL);
	view.abi_version = XCC_ABI_VERSION;
	view.candidates = NULL;
	CHECK(xcc_chooser_view_candidate(&view, 0) == NULL);
	/* An old producer's array contains only the original, padded prefix.
	 * Do not read the appended fields or assume the new sizeof as its stride. */
	struct OriginalRow
	{
		uint32_t struct_size, abi_version;
		uint64_t id;
		const char *subject, *issuer, *token, *reader, *expiry, *detail, *fingerprint;
		bool invalid;
	} original[2] = {0};
	CHECK(sizeof(original[0]) == XCC_CHOOSER_CANDIDATE_VIEW_V1_SIZE);
	for (size_t i = 0; i < 2; ++i)
	{
		original[i].struct_size = sizeof(original[i]);
		original[i].abi_version = XCC_ABI_VERSION;
		original[i].id = i + 7;
	}
	view.struct_size = XCC_CHOOSER_VIEW_V1_SIZE;
	view.candidates = (const XccChooserCandidateView*)original;
	view.n_candidates = 2;
	CHECK(xcc_chooser_view_candidate(&view, 1)->id == 8);
	CHECK((const void*)xcc_chooser_view_candidate(&view, 1) == &original[1]);

	struct ExtendedBytes
	{
		XccBytes bytes;
		uint64_t future;
	} issuers[2] = {0};
	for (size_t i = 0; i < 2; ++i)
	{
		issuers[i].bytes.struct_size = sizeof(issuers[i]);
		issuers[i].bytes.abi_version = XCC_ABI_VERSION;
	}
	XccAcquireSpec spec = {.struct_size = sizeof(spec),
						   .abi_version = XCC_ABI_VERSION,
						   .issuers = &issuers[0].bytes,
						   .n_issuers = 2};
	CHECK(xcc_acquire_spec_issuer(&spec, 1) == &issuers[1].bytes);
	CHECK(xcc_acquire_spec_issuer(&spec, 2) == NULL);
	CHECK(xcc_acquire_spec_issuer(NULL, 0) == NULL);
	issuers[0].bytes.struct_size = 0;
	CHECK(xcc_acquire_spec_issuer(&spec, 0) == NULL);
	issuers[0].bytes.struct_size = sizeof(XccBytes) - 1;
	CHECK(xcc_acquire_spec_issuer(&spec, 0) == NULL);
	issuers[0].bytes.struct_size = sizeof(issuers[0]);
	issuers[0].bytes.abi_version = XCC_ABI_VERSION + 1;
	CHECK(xcc_acquire_spec_issuer(&spec, 0) == NULL);
	issuers[0].bytes.abi_version = XCC_ABI_VERSION;
	spec.n_issuers = SIZE_MAX;
	CHECK(xcc_acquire_spec_issuer(&spec, SIZE_MAX / sizeof(issuers[0]) + 1) == NULL);
	spec.issuers = NULL;
	CHECK(xcc_acquire_spec_issuer(&spec, 0) == NULL);
	return EXIT_SUCCESS;
}
