# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
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
  # The consent window's display helpers. The window needs a display and a
  # person; the strings it renders do not, and they are where a hostile card
  # label would do its work.
  'chooser': 'test-chooser.c',
  # The two properties that make Decrypt safe to offer: one error for every
  # failure, and a per-grant budget. Skips itself without a SoftHSM fixture.
  'broker-decrypt': 'test-broker-decrypt.c',
  # A second AcquireCredential on a live session: the signature has to verify
  # against the certificate that was handed back. Skips without SoftHSM.
  'broker-regrant': 'test-broker-regrant.c',
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

# THE SHELL HELPERS IN tools/lib.sh. Two of them decide something dangerous --
# which portals.conf the development stack gets, and which directories it will
# remove -- and both were wrong at some point in a way no successful run showed.
test(
  'tools-lib',
  find_program('test-tools-lib.sh'),
  protocol: 'tap',
  env: test_env,
)

# THE SYSTEM-PROMPTER PATH. Only when the build found gcr-4, because without it
# there is no second implementation to test.
#
# It needs no display and no card: tests/pin-prompter.c stands up gcr's OWN
# server half on a private GTestDBus bus and answers from a script, so the
# retry, warning, final-try, attempt-cap and login-timeout rules are checked
# deterministically -- which is more than the GTK path can be without a person
# at a keyboard. It must never reach the session's real prompter; the module
# default is the in-process window and only this suite asks for "auto", on a bus
# it created itself.
if gcr_dep.found()
  pin_prompter = files('pin-prompter.c')

  exe = executable(
    'test-pin-system',
    ['test-pin-system.c'] + pin_prompter + fixture_util,
    dependencies: [certificate_service_dep, gcr_dep],
    include_directories: [config_inc, include_directories('..' / 'src'), include_directories('.')],
    c_args: test_args,
    install: false,
  )

  test('pin-system', exe, protocol: 'tap', env: test_env, timeout: 180)

  # The same prompter with a main() around it, so that tools/ui-smoke.sh can
  # run the whole stack -- frontend, backend, client -- against the
  # system-prompter path on its private bus. Not a test of its own.
  executable(
    'certificate-test-prompter',
    ['test-prompter-main.c'] + pin_prompter,
    dependencies: [glib_dep, gio_dep, gcr_dep],
    include_directories: [config_inc, include_directories('.')],
    install: false,
  )
endif
