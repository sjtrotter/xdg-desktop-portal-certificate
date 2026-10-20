# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>

# The frontend lives in xdg-desktop-portal's experimental/certificate branch; see docs/UPSTREAMING.md.

project(
  'xdg-desktop-portal-certificate',
  'c',
  version: '0.1.0',
  license: 'LGPL-2.1-or-later',
  meson_version: '>= 0.60.0',
  default_options: [
    'c_std=c11',
    'warning_level=2',
    'werror=false',
    'b_ndebug=if-release',
  ],
)

cc = meson.get_compiler('c')
gnome = import('gnome')

add_project_arguments(
  cc.get_supported_arguments([
    '-Wshadow',
    '-Wpointer-arith',
    '-Wstrict-prototypes',
    '-Wmissing-prototypes',
    '-Wwrite-strings',
    '-Wformat=2',
    '-Wno-unused-parameter',
    '-Wno-declaration-after-statement',
  ]),
  language: 'c',
)

prefix = get_option('prefix')
datadir = prefix / get_option('datadir')
libdir = prefix / get_option('libdir')
libexecdir = prefix / get_option('libexecdir')
dbus_service_dir = datadir / 'dbus-1' / 'services'
dbus_interfaces_dir = datadir / 'dbus-1' / 'interfaces'

portal_dir = datadir / 'xdg-desktop-portal' / 'portals'

glib_dep = dependency('glib-2.0', version: '>= 2.80')
gobject_dep = dependency('gobject-2.0', version: '>= 2.80')
gio_dep = dependency('gio-2.0', version: '>= 2.80')
gio_unix_dep = dependency('gio-unix-2.0', version: '>= 2.80')

# Module loading does not scope access; see docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md.
p11kit_dep = dependency('p11-kit-1', version: '>= 0.23')
gnutls_dep = dependency('gnutls', version: '>= 3.6')
# Prefer -Dservice=false for the SDK alone; retain the original auto_features shortcut.
service_enabled = get_option('service') and not get_option('auto_features').disabled()
if service_enabled
  gtk_dep = dependency('gtk4', version: '>= 4.14')
  adw_dep = dependency('libadwaita-1', version: '>= 1.4')

  # gcr-4 enables the system PIN prompter; see docs/SECURITY.md for its trust boundary.
  gcr_dep = dependency('gcr-4', version: '>= 4.0', required: get_option('gcr'))

  gtk_wayland_dep = dependency('gtk4-wayland', required: false)
  gtk_x11_dep = dependency('gtk4-x11', required: false)
  x11_dep = dependency('x11', required: false)
endif

config = configuration_data()
config.set_quoted('PACKAGE_VERSION', meson.project_version())
config.set('HAVE_GTK_WAYLAND', service_enabled and gtk_wayland_dep.found() ? 1 : 0)
config.set('HAVE_GTK_X11', (service_enabled and gtk_x11_dep.found() and x11_dep.found()) ? 1 : 0)
config.set('HAVE_GCR', service_enabled and gcr_dep.found() ? 1 : 0)
configure_file(output: 'config.h', configuration: config)

config_inc = include_directories('.')

# Bare module names resolve only within p11-kit's module directory.
p11kit_module_path = p11kit_dep.get_variable(
  pkgconfig: 'p11_module_path',
  default_value: libdir / 'pkcs11',
)
p11kit_module_configs = p11kit_dep.get_variable(
  pkgconfig: 'p11_module_configs',
  default_value: datadir / 'p11-kit' / 'modules',
)

p11_module_path = get_option('p11_module_path')
if p11_module_path == ''
  p11_module_path = libdir / 'pkcs11'
endif

p11_module_configs = get_option('p11_module_configs')
if p11_module_configs == ''
  p11_module_configs = datadir / 'p11-kit' / 'modules'
endif

if service_enabled
  subdir('data')
endif
subdir('src')
subdir('tests')

if service_enabled
  install_data(
    'tools/certificate-e2e.py',
    install_dir: get_option('datadir') / 'xdg-desktop-portal-certificate',
    install_mode: 'rwxr-xr-x',
  )
endif

summary(
  {
    'standalone service / GTK UI': service_enabled,
    'glib-2.0': glib_dep.version(),
    'gio-2.0': gio_dep.version(),
    'p11-kit-1': p11kit_dep.version(),
    'gnutls': gnutls_dep.version(),
  },
  section: 'dependencies',
)

if service_enabled
  summary(
    {
      'gtk4': gtk_dep.version(),
      'libadwaita-1': adw_dep.version(),
      'gtk4-wayland (xdg_foreign parenting)': gtk_wayland_dep.found() ? gtk_wayland_dep.version() : 'not found',
      'gtk4-x11 (XID parenting)': (gtk_x11_dep.found() and x11_dep.found()) ? gtk_x11_dep.version() : 'not found',
      'gcr-4 (--pin-prompt=system)': gcr_dep.found() ? gcr_dep.version() : 'not found',
    },
    section: 'UI dependencies',
  )
  summary(
    {
      'backend bus name': 'org.freedesktop.impl.portal.desktop.certificate',
      'impl interface': 'org.freedesktop.impl.portal.experimental.Certificate1',
      'object path': '/org/freedesktop/portal/desktop',
      'portal file': portal_dir / 'certificate.portal',
      'frontend': 'xdg-desktop-portal, branch experimental/certificate; needs XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=Certificate1',
      'public interface (frontend)': 'org.freedesktop.portal.experimental.Certificate1',
      'public object path (frontend)': '/org/freedesktop/portal/desktop',
      'core contract': 'credential selection + brokered Sign',
      'PKCS#11 facade': 'deferred; OpenPkcs11Endpoint is not in the branch interface',
      'client-side PKCS#11 module': p11_module_path / 'libpkcs11-portal-certificate.so',
      'p11-kit module file': p11_module_configs / 'xdg-desktop-portal-certificate.module',
      'p11-kit reports its module dir as': p11kit_module_path,
      'p11-kit reports its module-file dir as': p11kit_module_configs,
    },
    section: 'interfaces',
  )

  summary(
    {
      'chooser and PIN prompt': true,
      'brokered Sign': true,
      'PKCS#11 compatibility facade': false,
      'client-side PKCS#11 module': true,
      'frontend branch merged upstream': false,
      'safe to depend on': false,
    },
    section: 'status',
    bool_yn: true,
  )

endif
