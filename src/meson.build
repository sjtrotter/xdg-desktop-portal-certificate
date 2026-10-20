# SPDX-License-Identifier: LGPL-2.1-or-later
certificate_log_args = ['-DG_LOG_DOMAIN="xdg-desktop-portal-certificate"']
certificate_deps = [glib_dep, gobject_dep, gio_dep, gio_unix_dep, p11kit_dep, gnutls_dep]
certificate_common_sources = files(
  'core/identity.c', 'redact.c', 'tokens/discovery.c', 'tokens/filter.c',
  'tokens/pkcs11-util.c', 'broker/mechanism.c',
)
certificate_core_sources = certificate_common_sources + files(
  'broker/device.c', 'broker/operations.c',
  'core/chooser.c', 'core/context.c', 'core/acquire.c', 'core/sign.c',
  'core/ui.c', 'core/provider-bridge.c', 'core/dispatch-glib.c',
  'core/chooser-format.c', 'core/pin.c', 'core/pin-format.c',
  'core/secret.c', 'core/session.c',
)
core_map = files('core/xdp-certificate-core.map')
certificate_sdk = shared_library(
  'xdp-certificate-core', certificate_core_sources,
  soversion: '0',
  gnu_symbol_visibility: 'hidden',
  c_args: certificate_log_args,
  dependencies: certificate_deps,
  include_directories: config_inc,
  # Static GObject types retain pointers into this DSO for the process lifetime.
  link_args: ['-Wl,-z,nodelete',
              '-Wl,--version-script,' + meson.current_source_dir() / 'core/xdp-certificate-core.map'],
  link_depends: core_map,
  install: true,
)
install_headers(
  'core/core.h', 'core/ui.h', 'core/secret.h', 'core/abi.h', 'core/dispatch-glib.h',
  subdir: 'xdp-certificate-core-0/xdp-certificate',
)
import('pkgconfig').generate(
  certificate_sdk,
  filebase: 'xdp-certificate-core-0',
  name: 'XDP Certificate Core',
  description: 'Toolkit-neutral certificate discovery, consent and brokered operations',
  version: meson.project_version(),
  subdirs: 'xdp-certificate-core-0',
  requires_private: ['glib-2.0 >= 2.80', 'gio-2.0 >= 2.80', 'p11-kit-1 >= 0.23', 'gnutls >= 3.6'],
)

# Tests need private APIs and linker --wrap seams. Nothing in this archive is installed.
certificate_test_sources = certificate_core_sources
if service_enabled
  impl_dbus_sources = gnome.gdbus_codegen(
    'xdp-impl-dbus',
    sources: [
      '../data/org.freedesktop.impl.portal.experimental.Certificate1.xml',
      '../data/org.freedesktop.impl.portal.Request.xml',
      '../data/org.freedesktop.impl.portal.Session.xml',
    ],
    interface_prefix: 'org.freedesktop.impl.portal.', namespace: 'XdpImpl',
  )
  certificate_adapter_sources = files('certificate-impl.c', 'request-impl.c', 'session-impl.c')
  certificate_test_sources += certificate_adapter_sources + impl_dbus_sources
endif
certificate_core = static_library(
  'certificate-core-private', certificate_test_sources,
  c_args: certificate_log_args, dependencies: certificate_deps,
  include_directories: config_inc, install: false,
)
certificate_core_dep = declare_dependency(
  link_with: certificate_core,
  include_directories: [config_inc, include_directories('.')],
  dependencies: certificate_deps,
  sources: service_enabled ? impl_dbus_sources[1] : [],
)

if service_enabled
  certificate_ui_sources = files('ui/chooser.c', 'ui/pin-backends.c', 'ui/pin-gtk.c', 'ui/external-window.c')
  certificate_ui_deps = [gtk_dep, adw_dep]
  if gcr_dep.found()
    certificate_ui_sources += files('ui/pin-system.c')
    certificate_ui_deps += gcr_dep
  endif
  if gtk_wayland_dep.found()
    certificate_ui_deps += gtk_wayland_dep
  endif
  if gtk_x11_dep.found() and x11_dep.found()
    certificate_ui_deps += [gtk_x11_dep, x11_dep]
  endif
  certificate_service = static_library(
    'certificate-service', certificate_ui_sources,
    c_args: certificate_log_args, dependencies: certificate_deps + certificate_ui_deps,
    include_directories: config_inc, install: false,
  )
  certificate_service_dep = declare_dependency(
    link_with: [certificate_service, certificate_core],
    sources: impl_dbus_sources[1],
    include_directories: [config_inc, include_directories('.')],
    dependencies: certificate_deps + certificate_ui_deps,
  )

  # The reference service shares the core. Legacy provider handles and CLI/wire
  # helpers stay private; only the typed xcc_* boundary crosses the DSO.
  certificate_helpers = static_library(
    'certificate-service-private',
    certificate_common_sources + files('core/pin-format.c', 'ui/legacy-bridge.c', 'ui/legacy-helpers.c'),
    gnu_symbol_visibility: 'hidden', c_args: certificate_log_args,
    dependencies: certificate_deps, include_directories: config_inc, install: false,
  )
  certificate_backend = executable(
    'xdg-desktop-portal-certificate',
    ['main.c'] + certificate_adapter_sources + impl_dbus_sources,
    c_args: certificate_log_args + ['-DXCC_SHARED_ADAPTER'],
    link_with: [certificate_service, certificate_helpers, certificate_sdk],
    dependencies: certificate_deps + certificate_ui_deps,
    include_directories: config_inc,
    install: true, install_dir: libexecdir,
  )
  subdir('module')
endif
