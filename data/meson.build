# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>

# The Certificate interface XML must match the frontend branch; see docs/IMPL-INTERFACE.md.
install_data(
  [
    'org.freedesktop.impl.portal.experimental.Certificate1.xml',
    'org.freedesktop.impl.portal.Request.xml',
    'org.freedesktop.impl.portal.Session.xml',
  ],
  install_dir: dbus_interfaces_dir,
)

configure_file(
  input: 'certificate.portal.in',
  output: 'certificate.portal',
  copy: true,
  install: true,
  install_dir: portal_dir,
)

configure_file(
  input: 'org.freedesktop.impl.portal.desktop.certificate.service.in',
  output: 'org.freedesktop.impl.portal.desktop.certificate.service',
  configuration: {'libexecdir': libexecdir},
  install: true,
  install_dir: dbus_service_dir,
)
