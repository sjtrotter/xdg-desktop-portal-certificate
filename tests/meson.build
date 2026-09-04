# SPDX-License-Identifier: GPL-2.0-or-later
#
# Tier 1 of tests/README.md: everything that needs no card and no display, so it
# can run in CI and on a machine with an empty reader. The card path is
# exercised by tools/certificate-e2e.py through tools/dev-stack.sh; see
# docs/TESTING.md.

test_args = ['-DCERTIFICATE_FIXTURE_DIR="' + meson.current_source_dir() / 'fixtures' + '"']

fixture_util = files('fixture-util.c')

test_cases = {
  'filter': 'test-filter.c',
  'mechanism': 'test-mechanism.c',
  'redact': 'test-redact.c',
  # Skips itself when tools/softhsm-fixture.sh has not been run. It is the only
  # automated coverage C_Sign can have; the card path is the author's, in
  # docs/TESTING.md.
  'broker-device': 'test-broker-device.c',
}

foreach name, source : test_cases
  exe = executable(
    'test-' + name,
    [source] + fixture_util,
    link_with: certificate_core,
    dependencies: certificate_deps,
    include_directories: [config_inc, include_directories('..' / 'src'), include_directories('.')],
    c_args: test_args,
    install: false,
  )

  test(name, exe, protocol: 'tap', env: ['G_TEST_SRCDIR=' + meson.current_source_dir()])
endforeach
