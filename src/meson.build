# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>

# ONE gdbus-codegen run over all three impl interfaces, with the common prefix
# stripped, so the generated symbols read the way upstream's do:
#
#   org.freedesktop.impl.portal.experimental.Certificate -> XdpImplExperimentalCertificate
#   org.freedesktop.impl.portal.Request                  -> XdpImplRequest
#   org.freedesktop.impl.portal.Session                  -> XdpImplSession
impl_dbus_sources = gnome.gdbus_codegen(
  'xdp-impl-dbus',
  sources: [
    '../data/org.freedesktop.impl.portal.experimental.Certificate.xml',
    '../data/org.freedesktop.impl.portal.Request.xml',
    '../data/org.freedesktop.impl.portal.Session.xml',
  ],
  interface_prefix: 'org.freedesktop.impl.portal.',
  namespace: 'XdpImpl',
)

# Everything except main.c, so that the unit tests can link the same objects
# the binary uses rather than a copy of them.
certificate_core_sources = files(
  'certificate.c',
  'redact.c',
  'tokens/discovery.c',
  'tokens/filter.c',
  'tokens/pkcs11-util.c',
  'broker/device.c',
  'broker/mechanism.c',
)

certificate_service_sources = files(
  'certificate-impl.c',
  'request-impl.c',
  'session-impl.c',
  'broker/operations.c',
  'ui/chooser.c',
  'ui/pin.c',
  'ui/pin-gtk.c',
  'ui/external-window.c',
)

# The second PIN prompt, when the build found gcr-4. ui/pin.c compiles either
# way: what the option removes is an implementation, not the contract.
if gcr_dep.found()
  certificate_service_sources += files('ui/pin-system.c')
endif

certificate_deps = [
  glib_dep,
  gobject_dep,
  gio_dep,
  gio_unix_dep,
  p11kit_dep,
  gnutls_dep,
]

certificate_ui_deps = [gtk_dep, adw_dep]
if gcr_dep.found()
  certificate_ui_deps += gcr_dep
endif
if gtk_wayland_dep.found()
  certificate_ui_deps += gtk_wayland_dep
endif
if gtk_x11_dep.found() and x11_dep.found()
  certificate_ui_deps += [gtk_x11_dep, x11_dep]
endif

# The parts with no UI and no D-Bus in them, so the unit tests do not need a
# display or a bus to run.
certificate_core = static_library(
  'certificate-core',
  certificate_core_sources,
  dependencies: certificate_deps,
  include_directories: config_inc,
  install: false,
)

# The D-Bus and UI half, as a library rather than only as objects inside the
# binary, so that the integration tests can stand the impl object up on a
# private bus and drive the real code rather than a copy of it. Every finding in
# the D-Bus and lifecycle layer of the 2026 review was in code no test linked.
certificate_service = static_library(
  'certificate-service',
  certificate_service_sources + impl_dbus_sources,
  link_with: certificate_core,
  dependencies: certificate_deps + certificate_ui_deps,
  include_directories: config_inc,
  install: false,
)

certificate_service_dep = declare_dependency(
  link_with: [certificate_service, certificate_core],
  # The generated header, so that a dependent compiles after codegen has run.
  sources: impl_dbus_sources[1],
  include_directories: [config_inc, include_directories('.')],
  dependencies: certificate_deps + certificate_ui_deps,
)

executable(
  'xdg-desktop-portal-certificate',
  ['main.c'],
  dependencies: [certificate_service_dep],
  include_directories: config_inc,
  install: true,
  install_dir: libexecdir,
)
