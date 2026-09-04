# SPDX-License-Identifier: GPL-2.0-or-later

# smartcard-portal: a cryptographic credential broker for the Linux desktop,
# built in the shape xdg-desktop-portal uses.
#
# EXPERIMENTAL DESIGN SKETCH. Nothing is implemented. This build exists so that the
# skeleton compiles, the dependency picture is visible, and the interface XML has an
# install path -- not because there is anything to run.
#
# TWO BINARIES, because there are two processes:
#
#   certificate-portal-frontend   frontend/    the part that would move INTO
#                                            xdg-desktop-portal when accepted
#   certificate-portal-gtk        backends/gtk the part that would live in or beside
#                                            xdg-desktop-portal-gtk
#
# The umbrella exists because they are developed together and the impl interface
# between them is not stable. At upstreaming they separate; docs/UPSTREAMING.md.

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

prefix = get_option('prefix')
datadir = prefix / get_option('datadir')
# Both binaries are D-Bus activated and are not meant to be run from a shell, so they
# belong in libexecdir -- as xdg-desktop-portal and xdg-desktop-portal-gtk both do.
libexecdir = prefix / get_option('libexecdir')
dbus_service_dir = datadir / 'dbus-1' / 'services'
dbus_interfaces_dir = datadir / 'dbus-1' / 'interfaces'

# Where *.portal files and portals.conf live. Our-namespace equivalent of
# ${datadir}/xdg-desktop-portal/portals; see frontend/src/portal-impl.h and
# https://flatpak.github.io/xdg-desktop-portal/docs/portals.conf.html
portal_subdir = 'certificate-portal'
portal_dir = datadir / portal_subdir / 'portals'

# shared/ is header-only for now and is compiled into both binaries, exactly as
# xdg-desktop-portal's shared/ is compiled into its frontend and its portals.
shared_inc = include_directories('shared')

# Both stubs need only GLib. Everything else is declared so that the dependency picture
# is visible in the summary, and is unused: none of the components those libraries
# would serve exist yet.
glib_dep = dependency('glib-2.0', version: '>= 2.66')
gio_dep = dependency('gio-2.0', version: '>= 2.66', required: false)

# BACKEND dependencies. The frontend has none of these and must never grow them: it does
# not load PKCS#11 modules, does not talk to a card, and does not draw a window.
#
# p11-kit is used by the backend for MANAGED MODULE loading and for the RPC transport
# under the synthetic facade -- NOT for scoping. See
# docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md.
p11kit_dep = dependency('p11-kit-1', required: false)
# The chooser and the PIN prompt are backend-owned windows and are the controls that
# carry the security decision; see docs/IMPL-INTERFACE.md.
gtk_dep = dependency('gtk4', required: false)

# FRONTEND dependency, and only the frontend's: the permission store is where remembered
# certificate SELECTION lives, keyed by the app id the frontend established. There is no
# "remember PIN" and there never will be. The real
# org.freedesktop.impl.portal.PermissionStore is used when present, which needs no
# library -- libsecret remains listed only as the fallback that was considered and
# rejected in favour of the store the desktop's own revocation UI already lists.
secret_dep = dependency('libsecret-1', required: false)

subdir('frontend')
subdir('backends/gtk')

summary(
  {
    'glib-2.0 (required, both)': glib_dep.version(),
    'gio-2.0 (D-Bus, both)': gio_dep.found() ? gio_dep.version() : 'not found',
    'p11-kit-1 (BACKEND: tokens, RPC transport)': p11kit_dep.found() ? p11kit_dep.version() : 'not found',
    'gtk4 (BACKEND: chooser and PIN windows)': gtk_dep.found() ? gtk_dep.version() : 'not found',
    'libsecret-1 (rejected fallback, see above)': secret_dep.found() ? secret_dep.version() : 'not found',
  },
  section: 'smartcard-portal dependencies',
)

summary(
  {
    'frontend bus name': 'io.github.sjtrotter.portal.Certificate',
    'public interface': 'io.github.sjtrotter.portal.Certificate1 (EXPERIMENTAL)',
    'backend bus name': 'io.github.sjtrotter.impl.portal.Certificate.gtk',
    'impl interface': 'io.github.sjtrotter.impl.portal.Certificate1 (private)',
    'object path (both)': '/io/github/sjtrotter/portal/Certificate',
    'portal files': portal_dir,
    'core contract': 'credential selection + brokered Sign',
    'PKCS#11 facade': 'experimental, opt-in, milestone 2, backend-side',
  },
  section: 'smartcard-portal interfaces',
)

summary(
  {
    'implemented': false,
    'feasibility spike run': false,
    'proposed to freedesktop': false,
    'safe to depend on': false,
  },
  section: 'smartcard-portal status',
  bool_yn: true,
)
