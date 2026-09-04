# SPDX-License-Identifier: GPL-2.0-or-later

# xdg-desktop-portal-certificate: an out-of-tree BACKEND for the experimental
# org.freedesktop.impl.portal.experimental.Certificate portal interface.
#
# EXPERIMENTAL DESIGN SKETCH. Nothing is implemented. This build exists so that
# the skeleton compiles, the dependency picture is visible, and the interface
# XML, the .portal file and the D-Bus service file have install paths -- not
# because there is anything to run.
#
# ONE BINARY, because there is one process:
#
#   xdg-desktop-portal-certificate   src/   the chooser, the PIN prompt, token
#                                           discovery and the brokered
#                                           operations
#
# There is no frontend here any more. The portal frontend -- app id derivation,
# option validation, policy, the grant registry, the permission store, Request
# and Session lifecycle, backend selection -- is a branch of xdg-desktop-portal
# itself: experimental/certificate-webauthentication, commits 3f46e3c..661e441.
# See docs/decisions/0010-backend-only-frontend-lives-upstream.md and
# docs/UPSTREAMING.md.

project(
  'xdg-desktop-portal-certificate',
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

prefix = get_option('prefix')
datadir = prefix / get_option('datadir')
# The backend is D-Bus activated and is not meant to be run from a shell, so it
# belongs in libexecdir -- as xdg-desktop-portal-gtk's backend does.
libexecdir = prefix / get_option('libexecdir')
dbus_service_dir = datadir / 'dbus-1' / 'services'
dbus_interfaces_dir = datadir / 'dbus-1' / 'interfaces'

# THE REAL DIRECTORY. Out-of-tree backends install their .portal file into
# ${datadir}/xdg-desktop-portal/portals -- that is where the frontend looks
# (desktop-portal/xdp-portal-config.c:364) and there is nowhere else it would
# find it. xdg-desktop-portal-termfilechooser and xdg-desktop-portal-gtk both do
# exactly this.
portal_dir = datadir / 'xdg-desktop-portal' / 'portals'

# The stub needs only GLib. Everything else is declared so that the dependency
# picture is visible in the summary, and is unused: none of the components those
# libraries would serve exist yet.
glib_dep = dependency('glib-2.0', version: '>= 2.66')
gio_dep = dependency('gio-2.0', version: '>= 2.66', required: false)

# p11-kit is used for MANAGED MODULE loading and for the RPC transport under the
# synthetic facade -- NOT for scoping. See
# docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md.
p11kit_dep = dependency('p11-kit-1', required: false)
# The chooser and the PIN prompt are this backend's own windows and are the
# controls that carry the security decision; see docs/IMPL-INTERFACE.md.
gtk_dep = dependency('gtk4', required: false)

executable(
  'xdg-desktop-portal-certificate',
  sources: ['src/main.c'],
  dependencies: [glib_dep],
  install: true,
  install_dir: libexecdir,
)

# The impl interface description, installed where D-Bus interface XML lives so it
# can be introspected and reviewed. It is a VERBATIM COPY of the xdg-desktop-portal
# branch's file and must track it; the header in the file says so. Upstream keeps
# these in xdg-desktop-portal and backends read them from its pkg-config
# interfaces directory -- which is where this one comes from the day the branch
# lands. See docs/IMPL-INTERFACE.md.
install_data(
  'data/org.freedesktop.impl.portal.experimental.Certificate.xml',
  install_dir: dbus_interfaces_dir,
)

# Backend discovery. Upstream's gtk.portal.in has @-substitutions because its
# interface list is build-configurable; ours lists one interface unconditionally,
# so this is a copy. The .in name is kept so the file gains substitutions the day
# a second impl interface becomes optional.
configure_file(
  input: 'data/certificate.portal.in',
  output: 'certificate.portal',
  copy: true,
  install: true,
  install_dir: portal_dir,
)

# D-Bus activation. xdg-desktop-portal starts this name when a .portal file
# selects this backend; applications have no reason to hold it.
configure_file(
  input: 'data/org.freedesktop.impl.portal.desktop.certificate.service.in',
  output: 'org.freedesktop.impl.portal.desktop.certificate.service',
  configuration: {'libexecdir': libexecdir},
  install: true,
  install_dir: dbus_service_dir,
)

summary(
  {
    'glib-2.0 (required)': glib_dep.version(),
    'gio-2.0 (D-Bus)': gio_dep.found() ? gio_dep.version() : 'not found',
    'p11-kit-1 (tokens, RPC transport)': p11kit_dep.found() ? p11kit_dep.version() : 'not found',
    'gtk4 (chooser and PIN windows)': gtk_dep.found() ? gtk_dep.version() : 'not found',
  },
  section: 'dependencies',
)

summary(
  {
    'backend bus name': 'org.freedesktop.impl.portal.desktop.certificate',
    'impl interface': 'org.freedesktop.impl.portal.experimental.Certificate',
    'object path': '/org/freedesktop/portal/desktop',
    'portal file': portal_dir / 'certificate.portal',
    'frontend': 'xdg-desktop-portal, branch experimental/certificate-webauthentication',
    'public interface (frontend)': 'org.freedesktop.portal.experimental.Certificate',
    'frontend gate': 'XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate',
    'core contract': 'credential selection + brokered Sign',
    'PKCS#11 facade': 'deferred; OpenPkcs11Endpoint is not in the branch interface',
  },
  section: 'interfaces',
)

summary(
  {
    'implemented': false,
    'feasibility spike run': false,
    'frontend branch merged upstream': false,
    'safe to depend on': false,
  },
  section: 'status',
  bool_yn: true,
)
