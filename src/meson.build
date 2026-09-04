# SPDX-License-Identifier: GPL-2.0-or-later

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
  'broker/mechanism.c',
)

certificate_service_sources = files(
  'certificate-impl.c',
  'request-impl.c',
  'session-impl.c',
  'broker/operations.c',
  'ui/chooser.c',
  'ui/pin.c',
  'ui/external-window.c',
)

certificate_deps = [
  glib_dep,
  gobject_dep,
  gio_dep,
  gio_unix_dep,
  p11kit_dep,
  gnutls_dep,
]

certificate_ui_deps = [gtk_dep, adw_dep]
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

executable(
  'xdg-desktop-portal-certificate',
  ['main.c'] + certificate_service_sources + impl_dbus_sources,
  link_with: certificate_core,
  dependencies: certificate_deps + certificate_ui_deps,
  include_directories: config_inc,
  install: true,
  install_dir: libexecdir,
)
