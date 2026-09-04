# SPDX-License-Identifier: GPL-2.0-or-later
#
# Tier 1 of tests/README.md: everything that needs no card, so it can run in CI
# and on a machine with an empty reader. The card path is exercised by
# tools/certificate-e2e.py through tools/dev-stack.sh; see docs/TESTING.md.
#
# UNDER A SANITIZER, TOO. Three of the defects the 2026 review found were
# use-after-frees on cancellation paths, and none of them was reachable by a
# test that only checked return values:
#
#   meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false
#   meson test -C build-asan
#
# LeakSanitizer is pointed at tests/lsan.supp, because GTK, GnuTLS and p11-kit
# all keep one-time allocations alive for the life of the process and a leak
# report full of those is a leak report nobody reads.

test_args = ['-DCERTIFICATE_FIXTURE_DIR="' + meson.current_source_dir() / 'fixtures' + '"']

fixture_util = files('fixture-util.c')

test_env = [
  'G_TEST_SRCDIR=' + meson.current_source_dir(),
  'LSAN_OPTIONS=suppressions=' + meson.current_source_dir() / 'lsan.supp' + ':print_suppressions=0',
  'UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1',
]

# DBUS_SESSION_BUS_ADDRESS is deliberately NOT cleared here: the impl suite
# stands its own bus up with GTestDBus and overrides it for its own process,
# while an empty one makes GTK warn -- and g_test_init() makes warnings fatal.

# The parts that need neither the D-Bus layer nor GTK.
core_test_cases = {
  'filter': 'test-filter.c',
  'mechanism': 'test-mechanism.c',
  'redact': 'test-redact.c',
  # Skips itself when tools/softhsm-fixture.sh has not been run. It is the only
  # automated coverage C_Sign can have; the card path is the author's, in
  # docs/TESTING.md.
  'broker-device': 'test-broker-device.c',
}

foreach name, source : core_test_cases
  exe = executable(
    'test-' + name,
    [source] + fixture_util,
    link_with: certificate_core,
    dependencies: certificate_deps,
    include_directories: [config_inc, include_directories('..' / 'src'), include_directories('.')],
    c_args: test_args,
    install: false,
  )

  test(name, exe, protocol: 'tap', env: test_env)
endforeach

# The D-Bus boundary and the cancellation paths. These link the SERVICE, which
# is the code the four tests above never touched: certificate-impl.c,
# request-impl.c, session-impl.c, broker/operations.c and ui/pin.c.
service_test_cases = {
  'impl-dbus': 'test-impl-dbus.c',
  'cancellation': 'test-cancellation.c',
}

foreach name, source : service_test_cases
  exe = executable(
    'test-' + name,
    [source] + fixture_util,
    dependencies: [certificate_service_dep],
    include_directories: [config_inc, include_directories('..' / 'src'), include_directories('.')],
    c_args: test_args,
    install: false,
  )

  # 120 s rather than the default 30: the cancellation tests wait on real
  # worker threads, and a sanitized build is slow.
  test(name, exe, protocol: 'tap', env: test_env, timeout: 120)
endforeach
