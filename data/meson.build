# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>

# The impl interface descriptions, installed where D-Bus interface XML lives so
# they can be introspected and reviewed. The Certificate one is a VERBATIM COPY
# of the xdg-desktop-portal branch's file and must track it; the header in the
# file says so. Upstream keeps these in xdg-desktop-portal and backends read
# them from that project's pkg-config interfaces directory -- which is where
# they come from the day the branch lands. See docs/IMPL-INTERFACE.md.
install_data(
  [
    'org.freedesktop.impl.portal.experimental.Certificate.xml',
    'org.freedesktop.impl.portal.Request.xml',
    'org.freedesktop.impl.portal.Session.xml',
  ],
  install_dir: dbus_interfaces_dir,
)

# Backend discovery. Upstream's gtk.portal.in has @-substitutions because its
# interface list is build-configurable; ours lists one interface
# unconditionally, so this is a copy.
configure_file(
  input: 'certificate.portal.in',
  output: 'certificate.portal',
  copy: true,
  install: true,
  install_dir: portal_dir,
)

# D-Bus activation. xdg-desktop-portal starts this name when a .portal file
# selects this backend; applications have no reason to hold it.
configure_file(
  input: 'org.freedesktop.impl.portal.desktop.certificate.service.in',
  output: 'org.freedesktop.impl.portal.desktop.certificate.service',
  configuration: {'libexecdir': libexecdir},
  install: true,
  install_dir: dbus_service_dir,
)
