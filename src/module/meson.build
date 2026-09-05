# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
#
# THE CLIENT-SIDE PKCS#11 MODULE. It is loaded into the APPLICATION's process by
# p11-kit and forwards to the PUBLIC portal interface over D-Bus. It is not part
# of the backend and links none of it; see
# docs/decisions/0011-client-side-pkcs11-module.md.

module_sources = files(
  'der.c',
  'mechanism.c',
  'objects.c',
)

module_deps = [glib_dep, gobject_dep, gio_dep, gnutls_dep, p11kit_dep]

module_args = ['-DG_LOG_DOMAIN="' + 'pkcs11-portal-certificate' + '"']

# The parts with no D-Bus in them, so that the unit tests can link the same
# objects the module ships rather than a copy of them.
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

# ONLY C_GetFunctionList AND THE TWO 3.0 ENTRY POINTS ARE EXPORTED. An
# application that loads several PKCS#11 modules must not have one module's
# C_Sign resolve to another's, and a version script is the only thing that
# guarantees it.
module_link_args = []
if cc.has_link_argument('-Wl,--version-script,' + meson.current_source_dir() / 'pkcs11-portal-certificate.map')
  module_link_args += ['-Wl,--version-script,' + meson.current_source_dir() / 'pkcs11-portal-certificate.map']
endif

pkcs11_portal_module = shared_library(
  'pkcs11-portal-certificate',
  ['module.c', 'portal.c'],
  name_prefix: 'lib',
  dependencies: [module_core_dep],
  c_args: module_args,
  link_args: module_link_args,
  link_depends: files('pkcs11-portal-certificate.map'),
  install: true,
  install_dir: p11_module_path,
)

# The p11-kit module file. `module:` is the bare name when this build installs
# into p11-kit's own module directory, and an absolute path when it does not,
# because a relative name is resolved against p11-kit's directory and nothing
# else.
module_file_config = configuration_data()
if p11_module_path == p11kit_module_path
  module_file_config.set('module', 'libpkcs11-portal-certificate.so')
else
  module_file_config.set('module', p11_module_path / 'libpkcs11-portal-certificate.so')
endif

# THE FILE NAME IS PART OF THE CONTRACT with the web-auth backend, which names
# it in src/module/portal-token.h, and it is also the p11-kit module NAME that
# src/tokens/discovery.c refuses to load.
configure_file(
  input: 'xdg-desktop-portal-certificate.module.in',
  output: 'xdg-desktop-portal-certificate.module',
  configuration: module_file_config,
  install: true,
  install_dir: p11_module_configs,
)
