# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>

module_sources = files(
  'der.c',
  'mechanism.c',
  'objects.c',
  'portal.c',
)

module_deps = [glib_dep, gobject_dep, gio_dep, gnutls_dep, p11kit_dep]

module_args = ['-DG_LOG_DOMAIN="' + 'pkcs11-portal-certificate' + '"']

module_core = static_library(
  'pkcs11-portal-core',
  module_sources,
  dependencies: module_deps,
  c_args: module_args,
  install: false,
)

module_core_dep = declare_dependency(
  link_with: module_core,
  include_directories: include_directories('.'),
  dependencies: module_deps,
)

# Restrict exports to PKCS#11 entry points to prevent symbol collisions between loaded modules.
module_link_args = []
if cc.has_link_argument('-Wl,--version-script,' + meson.current_source_dir() / 'pkcs11-portal-certificate.map')
  module_link_args += ['-Wl,--version-script,' + meson.current_source_dir() / 'pkcs11-portal-certificate.map']
endif

pkcs11_portal_module = shared_library(
  'pkcs11-portal-certificate',
  ['module.c'],
  name_prefix: 'lib',
  dependencies: [module_core_dep],
  c_args: module_args,
  link_args: module_link_args,
  link_depends: files('pkcs11-portal-certificate.map'),
  install: true,
  install_dir: p11_module_path,
)

# Module paths outside p11-kit's search directory must be absolute.
module_file_config = configuration_data()
if p11_module_path == p11kit_module_path
  module_file_config.set('module', 'libpkcs11-portal-certificate.so')
else
  module_file_config.set('module', p11_module_path / 'libpkcs11-portal-certificate.so')
endif

# The configuration filename is a consumer contract and the backend's module exclusion name.
configure_file(
  input: 'xdg-desktop-portal-certificate.module.in',
  output: 'xdg-desktop-portal-certificate.module',
  configuration: module_file_config,
  install: true,
  install_dir: p11_module_configs,
)
