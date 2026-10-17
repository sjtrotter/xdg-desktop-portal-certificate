# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>

test_args = ['-DCERTIFICATE_FIXTURE_DIR="' + meson.current_source_dir() / 'fixtures' + '"']

fixture_util = files('fixture-util.c')

# Keep DBUS_SESSION_BUS_ADDRESS: an empty value makes GTK warn, and g_test_init() makes warnings fatal.
test_env = [
  'G_TEST_SRCDIR=' + meson.current_source_dir(),
  'LSAN_OPTIONS=suppressions=' + meson.current_source_dir() / 'lsan.supp' + ':print_suppressions=0',
  'UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1',
]

core_test_cases = {
  'filter': 'test-filter.c',
  'mechanism': 'test-mechanism.c',
  'redact': 'test-redact.c',
  'discovery-limits': 'test-discovery-limits.c',
  # Skip when the SoftHSM fixture is unavailable.
  'broker-device': 'test-broker-device.c',
}

foreach name, source : core_test_cases
  exe = executable(
    'test-' + name,
    [source] + fixture_util,
    link_with: certificate_core,
    dependencies: certificate_deps,
    include_directories: [config_inc, include_directories('..' / 'src'), include_directories('.')],
    c_args: test_args + certificate_log_args,
    install: false,
  )

  test(name, exe, protocol: 'tap', env: test_env)
endforeach

service_test_cases = {
  'impl-dbus': 'test-impl-dbus.c',
  'cancellation': 'test-cancellation.c',
  'chooser': 'test-chooser.c',
  'broker-decrypt': 'test-broker-decrypt.c',
  'broker-regrant': 'test-broker-regrant.c',
}

foreach name, source : service_test_cases
  exe = executable(
    'test-' + name,
    [source] + fixture_util,
    dependencies: [certificate_service_dep],
    include_directories: [config_inc, include_directories('..' / 'src'), include_directories('.')],
    c_args: test_args + certificate_log_args,
    install: false,
  )

  # Worker waits need a longer timeout under sanitizers.
  test(name, exe, protocol: 'tap', env: test_env, timeout: 120)
endforeach

exe = executable(
  'test-module',
  ['test-module.c'],
  dependencies: [module_core_dep],
  include_directories: [config_inc, include_directories('..' / 'src'), include_directories('.')],
  c_args: test_args,
  install: false,
)

test('module', exe, protocol: 'tap', env: test_env)

exe = executable(
  'test-module-portal',
  ['test-module-portal.c'],
  link_with: pkcs11_portal_module,
  dependencies: module_deps,
  include_directories: [config_inc, include_directories('..' / 'src'), include_directories('.')],
  c_args: test_args + ['-DPORTAL_MODULE_PATH="' + pkcs11_portal_module.full_path() + '"'],
  install: false,
)

test('module-portal', exe, protocol: 'tap', env: test_env, timeout: 120)

exe = executable(
  'fuzz-der',
  ['fuzz-der.c'],
  dependencies: [module_core_dep],
  include_directories: [config_inc, include_directories('..' / 'src'), include_directories('.')],
  c_args: test_args,
  install: false,
)

test('fuzz-der', exe, protocol: 'tap', env: test_env, timeout: 120)

# libFuzzer requires an explicit runtime limit and is not a Meson test.
if cc.get_id() == 'clang' and cc.has_link_argument('-fsanitize=fuzzer')
  executable(
    'fuzz-der-libfuzzer',
    ['fuzz-der.c'],
    dependencies: [module_core_dep],
    include_directories: [config_inc, include_directories('..' / 'src'), include_directories('.')],
    c_args: test_args + ['-DPKCS11_PORTAL_FUZZING_ENGINE=1', '-fsanitize=fuzzer-no-link'],
    link_args: ['-fsanitize=fuzzer'],
    install: false,
  )
endif

# tools/module-smoke.sh supplies the display and input needed to run this client.
if glib_dep.version().version_compare('>= 2.68')
  executable(
    'gtls-client',
    ['gtls-client.c'],
    dependencies: [glib_dep, gobject_dep, gio_dep],
    include_directories: [config_inc],
    install: false,
  )
endif

test(
  'tools-lib',
  find_program('test-tools-lib.sh'),
  protocol: 'tap',
  env: test_env,
)

test(
  'cli',
  find_program('test-cli.sh'),
  args: [certificate_backend, gcr_dep.found() ? 'gcr' : 'no-gcr'],
  protocol: 'tap',
  env: test_env,
)

# The scripted prompter runs on a private bus and must never reach the user's real prompter.
if gcr_dep.found()
  pin_prompter = files('pin-prompter.c')

  exe = executable(
    'test-pin-system',
    ['test-pin-system.c'] + pin_prompter + fixture_util,
    dependencies: [certificate_service_dep, gcr_dep],
    include_directories: [config_inc, include_directories('..' / 'src'), include_directories('.')],
    c_args: test_args + certificate_log_args,
    install: false,
  )

  test('pin-system', exe, protocol: 'tap', env: test_env, timeout: 180)

  executable(
    'certificate-test-prompter',
    ['test-prompter-main.c'] + pin_prompter,
    dependencies: [glib_dep, gio_dep, gcr_dep],
    include_directories: [config_inc, include_directories('.')],
    install: false,
  )
endif

# NSS is optional for normal builds; tools/nss-smoke.sh phase 4 requires this client.
nss_dep = dependency('nss', required: false)
if nss_dep.found()
  executable(
    'nss-refresh-client',
    ['nss-refresh-client.c'],
    dependencies: [nss_dep],
    install: false,
  )
endif
