# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>

impl_dbus_sources = gnome.gdbus_codegen(
  'xdp-impl-dbus',
  sources: [
    '../data/org.freedesktop.impl.portal.experimental.Certificate1.xml',
    '../data/org.freedesktop.impl.portal.Request.xml',
    '../data/org.freedesktop.impl.portal.Session.xml',
  ],
  interface_prefix: 'org.freedesktop.impl.portal.',
  namespace: 'XdpImpl',
)

certificate_log_args = ['-DG_LOG_DOMAIN="xdg-desktop-portal-certificate"']

# Core headers must remain free of GTK, libadwaita and gcr dependencies for headless tests.
certificate_core_sources = files(
  'certificate.c',
  'certificate-impl.c',
  'redact.c',
  'core/chooser.c',
  'core/context.c',
  'core/acquire.c',
  'core/sign.c',
  'core/ui.c',
  'ui/provider-bridge.c',
  'core/dispatch-glib.c',
  'core/chooser-format.c',
  'core/pin.c',
  'core/secret.c',
  'core/session.c',
  'request-impl.c',
  'session-impl.c',
  'broker/device.c',
  'broker/mechanism.c',
  'broker/operations.c',
  'tokens/discovery.c',
  'tokens/filter.c',
  'tokens/pkcs11-util.c',
)

certificate_ui_sources = files(
  'ui/chooser.c',
  'ui/pin-backends.c',
  'ui/pin-gtk.c',
  'ui/external-window.c',
)

if gcr_dep.found()
  certificate_ui_sources += files('ui/pin-system.c')
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

certificate_core = static_library(
  'certificate-core',
  certificate_core_sources + impl_dbus_sources,
  c_args: certificate_log_args,
  dependencies: certificate_deps,
  include_directories: config_inc,
  install: false,
)

certificate_core_dep = declare_dependency(
  link_with: certificate_core,
  # Dependents need the generated header before compiling.
  sources: impl_dbus_sources[1],
  include_directories: [config_inc, include_directories('.')],
  dependencies: certificate_deps,
)

certificate_service = static_library(
  'certificate-service',
  certificate_ui_sources,
  c_args: certificate_log_args,
  link_with: certificate_core,
  dependencies: certificate_deps + certificate_ui_deps,
  include_directories: config_inc,
  install: false,
)

certificate_service_dep = declare_dependency(
  link_with: [certificate_service, certificate_core],
  # Dependents need the generated header before compiling.
  sources: impl_dbus_sources[1],
  include_directories: [config_inc, include_directories('.')],
  dependencies: certificate_deps + certificate_ui_deps,
)

subdir('module')

certificate_backend = executable(
  'xdg-desktop-portal-certificate',
  ['main.c'],
  c_args: certificate_log_args,
  dependencies: [certificate_service_dep],
  include_directories: config_inc,
  install: true,
  install_dir: libexecdir,
)
