# SPDX-License-Identifier: GPL-2.0-or-later
#
# The reference BACKEND, laid out like xdg-desktop-portal-gtk: a D-Bus activatable
# executable, a .portal file naming the impl interfaces it implements, and one source
# file per portal. See docs/UPSTREAMING.md for where each piece lands.

executable(
  'smartcard-portal-gtk',
  sources: ['src/main.c'],
  include_directories: shared_inc,
  dependencies: [glib_dep],
  install: true,
  install_dir: libexecdir,
)

# The impl interface description. Upstream this file would live in xdg-desktop-portal's
# data/ and backends would consume it from the interfaces_dir pkg-config variable; while
# the interface is ours and unstable it ships with the backend that defines it, which is
# a deviation recorded in docs/UPSTREAMING.md.
install_data(
  'data/io.github.sjtrotter.impl.portal.Smartcard1.xml',
  install_dir: dbus_interfaces_dir,
)

# Backend discovery. The frontend scans ${datadir}/smartcard-portal/portals for *.portal
# files and reads DBusName and Interfaces from each.
# Upstream's gtk.portal.in has @-substitutions because its backend's interface list is
# build-configurable; ours lists one interface unconditionally, so this is a copy. The
# .in name is kept so the file gains substitutions the day a second impl interface
# becomes optional.
configure_file(
  input: 'data/gtk.portal.in',
  output: 'gtk.portal',
  copy: true,
  install: true,
  install_dir: portal_dir,
)

# D-Bus activation for the backend. Applications have no reason to hold this name.
configure_file(
  input: 'data/io.github.sjtrotter.impl.portal.desktop.gtk.service.in',
  output: 'io.github.sjtrotter.impl.portal.desktop.gtk.service',
  configuration: {'libexecdir': libexecdir},
  install: true,
  install_dir: dbus_service_dir,
)
