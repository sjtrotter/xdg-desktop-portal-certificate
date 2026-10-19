/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "core/context-private.h"
#include "fixture-util.h"

static void assert_metadata(CertificateCandidate* candidate)
{
	XccCandidate* snapshot = xcc_candidate_snapshot(candidate);
	const XccCandidateInfo* info = xcc_candidate_info(snapshot);
	const CertificateToken* token = candidate->token;
	g_assert_cmpuint(info->abi_version, ==, XCC_ABI_VERSION);
	g_assert_cmpuint(info->struct_size, >=,
	                 offsetof(XccCandidateInfo, token_reader) + sizeof(const char*));
	g_assert_cmpstr(info->token_label, ==, token->label != NULL ? token->label : "");
	g_assert_cmpstr(info->token_manufacturer, ==,
	                token->manufacturer != NULL ? token->manufacturer : "");
	g_assert_cmpstr(info->token_model, ==, token->model != NULL ? token->model : "");
	g_assert_cmpstr(info->token_reader, ==, token->reader_name != NULL ? token->reader_name : "");
	g_assert_cmpint(info->protected_path, ==, token->protected_authentication_path);
	xcc_candidate_unref(snapshot);
}

static void test_original_and_absent(void)
{
	g_autoptr(CertificateCandidate) candidate =
	    certificate_test_candidate("client-auth-rsa.pem", TRUE, FALSE);
	g_free(candidate->token->label);
	candidate->token->label = g_strdup("Original\tToken\nLabel");
	assert_metadata(candidate);
	XccCandidate* snapshot = xcc_candidate_snapshot(candidate);
	g_assert_cmpstr(xcc_candidate_info(snapshot)->token, !=,
	                xcc_candidate_info(snapshot)->token_label);
	xcc_candidate_unref(snapshot);
	g_clear_pointer(&candidate->token->label, g_free);
	g_clear_pointer(&candidate->token->manufacturer, g_free);
	g_clear_pointer(&candidate->token->model, g_free);
	g_clear_pointer(&candidate->token->reader_name, g_free);
	assert_metadata(candidate);
}

static void test_softhsm(void)
{
	const char* directory = g_getenv("SOFTHSM_FIXTURE_DIR");
	g_autofree char* fallback = g_build_filename(g_get_tmp_dir(), "xdp-certificate-softhsm", NULL);
	if (directory == NULL)
		directory = fallback;
	g_autofree char* config = g_build_filename(directory, "softhsm2.conf", NULL);
	g_autofree char* module_path = g_build_filename(directory, "module-path", NULL);
	g_autofree char* module = g_strdup(g_getenv("SOFTHSM_MODULE"));
	if (module == NULL)
		g_file_get_contents(module_path, &module, NULL, NULL);
	if (module == NULL || !g_file_test(config, G_FILE_TEST_IS_REGULAR))
	{
		g_test_skip("no SoftHSM fixture; run tools/softhsm-fixture.sh");
		return;
	}
	g_strchomp(module);
	g_setenv("SOFTHSM2_CONF", config, TRUE);
	const char* modules[] = {module, NULL};
	g_autoptr(GError) error = NULL;
	g_autoptr(CertificateTokens) tokens = certificate_tokens_new(modules, &error);
	g_assert_no_error(error);
	g_assert_nonnull(tokens);
	certificate_tokens_set_allow_software(tokens, TRUE);
	g_autoptr(GPtrArray) candidates = certificate_tokens_enumerate(tokens, NULL, &error);
	g_assert_no_error(error);
	if (candidates->len == 0)
	{
		g_test_skip("the SoftHSM fixture has no certificates; rebuild it");
		return;
	}
	for (guint i = 0; i < candidates->len; i++)
		assert_metadata(g_ptr_array_index(candidates, i));
}

int main(int argc, char** argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/sdk/token-metadata/original-and-absent", test_original_and_absent);
	g_test_add_func("/sdk/token-metadata/softhsm", test_softhsm);
	return g_test_run();
}
