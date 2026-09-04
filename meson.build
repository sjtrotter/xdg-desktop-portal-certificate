# SPDX-License-Identifier: GPL-2.0-or-later

# xdg-desktop-portal-certificate: an out-of-tree BACKEND for the experimental
# org.freedesktop.impl.portal.experimental.Certificate portal interface.
#
# ONE BINARY, because there is one process:
#
#   xdg-desktop-portal-certificate   src/   the chooser, the PIN prompt, token
#                                           discovery and the brokered
#                                           operations
#
# There is no frontend here. The portal frontend -- app id derivation, option
# validation, policy, the grant registry, the permission store, Request and
# Session lifecycle, backend selection -- is a branch of xdg-desktop-portal
# itself: experimental/certificate-webauthentication, commits 3f46e3c..661e441.
# See docs/decisions/0010-backend-only-frontend-lives-upstream.md and
# docs/UPSTREAMING.md.
#
# LIBDEX IS DELIBERATELY NOT A DEPENDENCY. The frontend branch uses it for its
# fibers; backends do not, and no released distribution ships it as a backend
# dependency. Everything here is plain GLib/GIO async plus GTask worker threads
# for the PKCS#11 calls, which is what xdg-desktop-portal-gtk does.

project(
  'xdg-desktop-portal-certificate',
  'c',
  version: '0.1.0',
  license: 'GPL-2.0-or-later',
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
# The backend is D-Bus activated and is not meant to be run from a shell, so it
# belongs in libexecdir -- as xdg-desktop-portal-gtk's backend does.
libexecdir = prefix / get_option('libexecdir')
dbus_service_dir = datadir / 'dbus-1' / 'services'
dbus_interfaces_dir = datadir / 'dbus-1' / 'interfaces'

# THE REAL DIRECTORY. Out-of-tree backends install their .portal file into
# ${datadir}/xdg-desktop-portal/portals -- that is where the frontend looks
# (desktop-portal/xdp-portal-config.c:364) and there is nowhere else it would
# find it.
portal_dir = datadir / 'xdg-desktop-portal' / 'portals'

glib_dep = dependency('glib-2.0', version: '>= 2.66')
gobject_dep = dependency('gobject-2.0', version: '>= 2.66')
gio_dep = dependency('gio-2.0', version: '>= 2.66')
gio_unix_dep = dependency('gio-unix-2.0', version: '>= 2.66')

# p11-kit is used for MANAGED MODULE loading -- NOT for scoping. See
# docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md.
p11kit_dep = dependency('p11-kit-1', version: '>= 0.23')
# GnuTLS parses the DER the token hands back: subject, issuer, validity, key
# usage, extended key usage, key type. Nothing is signed or verified with it.
gnutls_dep = dependency('gnutls', version: '>= 3.6')
# The chooser and the PIN prompt are this backend's own windows and are the
# controls that carry the security decision; see docs/IMPL-INTERFACE.md.
gtk_dep = dependency('gtk4', version: '>= 4.10')
adw_dep = dependency('libadwaita-1', version: '>= 1.4')

# Parenting a dialog to the requesting application's window. Both are optional:
# a backend on a display server it was not built for simply draws an unparented
# window, which the chooser is required to do anyway for an invalid handle.
# THE SYSTEM PROMPTER. Optional, and the option it enables does not exist
# without it: with gcr-4 present the backend can hand the PIN FIELD to the
# desktop shell (org.gnome.keyring.SystemPrompter) instead of drawing it
# itself. What that moves and what it does not is docs/SECURITY.md.
gcr_dep = dependency('gcr-4', version: '>= 4.0', required: get_option('gcr'))

gtk_wayland_dep = dependency('gtk4-wayland', required: false)
gtk_x11_dep = dependency('gtk4-x11', required: false)
x11_dep = dependency('x11', required: false)

config = configuration_data()
config.set_quoted('PACKAGE_VERSION', meson.project_version())
config.set('HAVE_GTK_WAYLAND', gtk_wayland_dep.found() ? 1 : 0)
config.set('HAVE_GTK_X11', (gtk_x11_dep.found() and x11_dep.found()) ? 1 : 0)
config.set('HAVE_GCR', gcr_dep.found() ? 1 : 0)
configure_file(output: 'config.h', configuration: config)

config_inc = include_directories('.')

subdir('data')
subdir('src')
subdir('tests')

install_data(
  'tools/certificate-e2e.py',
  install_dir: get_option('datadir') / 'xdg-desktop-portal-certificate',
  install_mode: 'rwxr-xr-x',
)

summary(
  {
    'glib-2.0': glib_dep.version(),
    'gio-2.0': gio_dep.version(),
    'p11-kit-1': p11kit_dep.version(),
    'gnutls': gnutls_dep.version(),
    'gtk4': gtk_dep.version(),
    'libadwaita-1': adw_dep.version(),
    'gtk4-wayland (xdg_foreign parenting)': gtk_wayland_dep.found() ? gtk_wayland_dep.version() : 'not found',
    'gtk4-x11 (XID parenting)': (gtk_x11_dep.found() and x11_dep.found()) ? gtk_x11_dep.version() : 'not found',
    'gcr-4 (--pin-prompt=system)': gcr_dep.found() ? gcr_dep.version() : 'not found',
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
    'chooser and PIN prompt': true,
    'brokered Sign / Decrypt': true,
    'PKCS#11 compatibility facade': false,
    'frontend branch merged upstream': false,
    'safe to depend on': false,
  },
  section: 'status',
  bool_yn: true,
)
