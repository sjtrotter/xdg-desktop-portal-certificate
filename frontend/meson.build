# SPDX-License-Identifier: GPL-2.0-or-later
#
# The portal FRONTEND. This is the part that would move INTO xdg-desktop-portal:
# frontend/src/*.c becomes desktop-portal/smartcard.c and friends, and
# frontend/data/*.xml becomes data/org.freedesktop.portal.Certificate.xml. See
# docs/UPSTREAMING.md.
#
# It links GLib and nothing else, on purpose. A frontend that could load a PKCS#11
# module or draw a window would be a frontend that has to know what a card is, and the
# split would be decorative.

executable(
  'certificate-portal-frontend',
  sources: ['src/main.c'],
  include_directories: shared_inc,
  dependencies: [glib_dep],
  install: true,
  install_dir: libexecdir,
)

# The public interface description, installed where D-Bus interface XML lives so it can
# be introspected and reviewed. This is NOT an accepted freedesktop interface.
install_data(
  'data/io.github.sjtrotter.portal.Certificate1.xml',
  install_dir: dbus_interfaces_dir,
)

# D-Bus activation for the frontend's well-known name -- the only name applications talk
# to.
configure_file(
  input: 'data/io.github.sjtrotter.portal.Certificate.service.in',
  output: 'io.github.sjtrotter.portal.Certificate.service',
  configuration: {'libexecdir': libexecdir},
  install: true,
  install_dir: dbus_service_dir,
)

# portals.conf.example is deliberately NOT installed: an installation with one backend
# does not need a configuration file, and one with two should be choosing on purpose.
# See frontend/src/portal-impl.h for the search order.
