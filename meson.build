# SPDX-License-Identifier: GPL-2.0-or-later

# smartcard-portal: a cryptographic credential broker for the Linux desktop.
#
# EXPERIMENTAL DESIGN SKETCH. Nothing is implemented. This build exists so that the
# skeleton compiles, the dependency picture is visible, and the interface XML has an
# install path -- not because there is anything to run.

project(
  'smartcard-portal',
  'c',
  version: '0.0.0',
  license: 'GPL-2.0-or-later',
  meson_version: '>= 0.60.0',
  default_options: [
    'c_std=c11',
    'warning_level=3',
    'werror=false',
    'b_ndebug=if-release',
  ],
)

cc = meson.get_compiler('c')

add_project_arguments(
  cc.get_supported_arguments([
    '-Wshadow',
    '-Wpointer-arith',
    '-Wstrict-prototypes',
    '-Wmissing-prototypes',
    '-Wwrite-strings',
    '-Wformat=2',
  ]),
  language: 'c',
)

# The stub needs only GLib. Everything else is declared so that the dependency picture
# is visible in the summary, and is unused: none of the components those libraries
# would serve exist yet.
glib_dep = dependency('glib-2.0', version: '>= 2.66')
gio_dep = dependency('gio-2.0', version: '>= 2.66', required: false)

# src/tokens/, src/broker/, src/export/. p11-kit is used for MANAGED MODULE loading and
# for the RPC transport under the synthetic facade -- NOT for scoping. See
# docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md.
p11kit_dep = dependency('p11-kit-1', required: false)

# src/ui/. The chooser and the PIN prompt are service-owned windows and are the
# controls that carry the security decision; see docs/INTERFACE.md.
gtk_dep = dependency('gtk4', required: false)

# src/grant/. Only ever for selection MEMORY -- which certificate the user picked.
# Never for a PIN. There is no "remember PIN" and there never will be.
secret_dep = dependency('libsecret-1', required: false)

executable(
  'smartcard-portal',
  sources: ['src/main.c'],
  dependencies: [glib_dep],
  install: true,
)

# The experimental interface description, installed where D-Bus interface XML lives so
# it can be introspected and reviewed. This is NOT an accepted freedesktop interface.
install_data(
  'data/io.github.sjtrotter.Smartcard1.xml',
  install_dir: get_option('datadir') / 'dbus-1' / 'interfaces',
)

configure_file(
  input: 'data/io.github.sjtrotter.Smartcard1.service.in',
  output: 'io.github.sjtrotter.Smartcard1.service',
  configuration: {'libexecdir': get_option('prefix') / get_option('bindir')},
  install: true,
  install_dir: get_option('datadir') / 'dbus-1' / 'services',
)

summary(
  {
    'glib-2.0 (required)': glib_dep.version(),
    'gio-2.0 (D-Bus transaction layer)': gio_dep.found() ? gio_dep.version() : 'not found',
    'p11-kit-1 (tokens, RPC transport)': p11kit_dep.found() ? p11kit_dep.version() : 'not found',
    'gtk4 (chooser and PIN windows)': gtk_dep.found() ? gtk_dep.version() : 'not found',
    'libsecret-1 (selection memory only)': secret_dep.found() ? secret_dep.version() : 'not found',
  },
  section: 'smartcard-portal dependencies',
)

summary(
  {
    'bus name': 'io.github.sjtrotter.Smartcard1',
    'object path': '/io/github/sjtrotter/Smartcard1',
    'interface version': '1 (EXPERIMENTAL, not a freedesktop portal)',
    'core contract': 'credential selection + brokered Sign',
    'PKCS#11 facade': 'experimental, opt-in, milestone 2',
  },
  section: 'smartcard-portal interface',
)

summary(
  {
    'implemented': false,
    'feasibility spike run': false,
    'safe to depend on': false,
  },
  section: 'smartcard-portal status',
  bool_yn: true,
)
