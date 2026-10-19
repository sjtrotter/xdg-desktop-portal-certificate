#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Exercise the installed SDK, without build-tree headers or libraries."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

HEADERS = ('abi.h', 'secret.h', 'core.h', 'ui.h', 'dispatch-glib.h')
PUBLIC_NODE = 'XDP_CERTIFICATE_CORE_0'
PRIVATE_NODE = 'XDP_CERTIFICATE_CORE_PRIVATE_0'
# Deliberately independent of the linker map: changes to this internal interface
# must update the expected list as well as the service and library from the same build.
PRIVATE_SYMBOLS = (
    'xcc_adapter_settings',
    'xcc_candidate_internal',
    'xcc_context_new_for_tokens',
    'xcc_session_check_principal',
    'xcc_session_invalidate',
    'xcc_session_is_closed',
    'xcc_session_new_legacy',
    'xcc_session_set_invalidated_callback',
    'xcc_sign_async_parsed',
)
STRUCTS = ('XccError', 'XccDispatch', 'XccBytes', 'XccCandidateInfo', 'XccSessionSpec',
           'XccPrincipal', 'XccAcquireSpec', 'XccSignSpec', 'XccResult', 'XccConfig',
           'XccChooserCandidateView', 'XccChooserView', 'XccPinView', 'XccWarning', 'XccUiV1')
# Freeze the original candidate prefix independently of the installed header.
CANDIDATE_PREFIX = '''typedef struct {
    uint32_t struct_size, abi_version;
    XccBytes certificate;
    const char *subject, *issuer, *token, *reader, *key_type, *key_curve;
    uint32_t key_size;
    bool key_curve_present;
    const char *const *mechanisms;
    int64_t not_before, not_after;
    bool protected_path;
} CandidatePrefix;
'''
CANDIDATE_PREFIX_FIELDS = ('struct_size', 'abi_version', 'certificate', 'subject', 'issuer',
                           'token', 'reader', 'key_type', 'key_curve', 'key_size',
                           'key_curve_present', 'mechanisms', 'not_before', 'not_after',
                           'protected_path')
TOKEN_FIELDS = ('token_label', 'token_manufacturer', 'token_model', 'token_reader')


def run(command, **kwargs):
    print(shlex.join(str(arg) for arg in command), flush=True)
    return subprocess.run(command, check=True, text=True, **kwargs)


def output(command, **kwargs):
    return run(command, stdout=subprocess.PIPE, **kwargs).stdout.strip()


def stage(build, dest):
    run(['meson', 'install', '-C', str(build), '--no-rebuild', '--destdir', str(dest)])
    libraries = list(dest.rglob('libxdp-certificate-core.so.0'))
    assert len(libraries) == 1, libraries
    library = libraries[0]
    pcs = list(dest.rglob('xdp-certificate-core-0.pc'))
    assert len(pcs) == 1, pcs
    env = dict(os.environ, PKG_CONFIG_PATH=str(pcs[0].parent),
               PKG_CONFIG_SYSROOT_DIR=str(dest))
    includes = list(dest.rglob('xdp-certificate-core-0/xdp-certificate'))
    assert len(includes) == 1, includes
    assert sorted(path.name for path in includes[0].iterdir()) == sorted(HEADERS)
    return library, env, includes[0].parent


def public_symbols(include):
    # Installed exported declarations use XCC_API. Exclude static inline helpers
    # and comments, and allow return types/declarations to span multiple lines.
    names = set()
    for header in HEADERS:
        source = (include / 'xdp-certificate' / header).read_text()
        source = re.sub(r'/\*.*?\*/|//[^\n]*', '', source, flags=re.DOTALL)
        declarations = re.findall(r'^\s*XCC_API\b([^;{}]*);', source, flags=re.MULTILINE)
        for declaration in declarations:
            matches = re.findall(r'\b(xcc_\w+)\s*\(', declaration)
            # Fail on an unrecognized declaration instead of silently omitting it
            # from the expected ABI. Each entry point has one installed declaration.
            assert len(matches) == 1, (header, declaration)
            name = matches[0]
            assert name not in names, (header, name)
            names.add(name)
    assert names, 'No public declarations found in installed headers'
    return names


def symbols(library, include):
    public = public_symbols(include)
    assert not public.intersection(PRIVATE_SYMBOLS), public.intersection(PRIVATE_SYMBOLS)
    names = [line.split()[-1] for line in output(['nm', '-D', '--defined-only', str(library)]).splitlines()]
    expected = [PUBLIC_NODE, PRIVATE_NODE] + [name + '@@' + PUBLIC_NODE for name in public] + [
        name + '@@' + PRIVATE_NODE for name in PRIVATE_SYMBOLS]
    assert sorted(names) == sorted(expected), {
        'missing': sorted(set(expected) - set(names)),
        'unexpected': sorted(set(names) - set(expected)),
        'actual': names,
    }
    dynamic = output(['readelf', '-d', str(library)])
    assert re.search(r'\(SONAME\).*\[libxdp-certificate-core\.so\.0\]', dynamic), dynamic
    assert re.search(r'\(FLAGS_1\).*\bNODELETE\b', dynamic), dynamic


def dependencies(library):
    needed = output(['readelf', '-d', str(library)])
    assert not re.search(r'\(NEEDED\).*?(gtk|adwaita|gcr)', needed, re.IGNORECASE), needed
    linked = output(['ldd', str(library)])
    assert not re.search(r'^\s*lib(?:gtk|adwaita|gcr)', linked, re.IGNORECASE | re.MULTILINE), linked


def compile_headers(args, directory, include):
    for language, compiler, standard in [('c', args.cc_arg, 'c11'), ('c++', [args.cxx], 'c++17')]:
        for header in HEADERS:
            source = directory / ('header-' + header + '.' + ('cc' if language == 'c++' else 'c'))
            source.write_text('#include <xdp-certificate/' + header + '>\nint main(void) { return 0; }\n')
            flags = []
            if header == 'dispatch-glib.h':
                # The optional GLib bridge alone needs the host GLib development headers.
                flags = shlex.split(output(['pkg-config', '--cflags', 'glib-2.0']))
            run(compiler + ['-x', language, '-std=' + standard, '-Wall', '-Wextra', '-Werror',
                            '-I' + str(include)] + flags + ['-fsyntax-only', str(source)])
        source = directory / ('abi-layout.' + ('cc' if language == 'c++' else 'c'))
        assertion = 'static_assert' if language == 'c++' else '_Static_assert'
        source.write_text('#include <xdp-certificate/ui.h>\n#include <stddef.h>\n' + ''.join(
            f'{assertion}(offsetof({struct}, struct_size) == 0, "struct_size first");\n'
            f'{assertion}(offsetof({struct}, abi_version) == sizeof(uint32_t), "abi_version second");\n'
            for struct in STRUCTS) + CANDIDATE_PREFIX + ''.join(
                f'{assertion}(offsetof(XccCandidateInfo, {field}) == '
                f'offsetof(CandidatePrefix, {field}), "candidate prefix: {field}");\n'
                for field in CANDIDATE_PREFIX_FIELDS) + ''.join(
                f'{assertion}(offsetof(XccCandidateInfo, {field}) == '
                f'sizeof(CandidatePrefix) + {index} * sizeof(const char *), '
                f'"appended metadata: {field}");\n'
                for index, field in enumerate(TOKEN_FIELDS)))
        run(compiler + ['-x', language, '-std=' + standard, '-Wall', '-Wextra', '-Werror',
                        '-I' + str(include), '-fsyntax-only', str(source)])


def consumers(args, directory, library, env):
    cflags = shlex.split(output(['pkg-config', '--cflags', 'xdp-certificate-core-0'], env=env))
    libs = shlex.split(output(['pkg-config', '--libs', 'xdp-certificate-core-0'], env=env))
    options = json.loads(output(['meson', 'introspect', '--buildoptions', str(args.build)]))
    sanitizers = next(option['value'] for option in options if option['name'] == 'b_sanitize')
    if isinstance(sanitizers, str):
        sanitizers = sanitizers.split(',')
    sanitizers = [name for name in sanitizers if name != 'none']
    instrumentation = ['-fsanitize=' + ','.join(sanitizers)] if sanitizers else []
    for language, compiler, standard in [('c', args.cc_arg, 'c11'), ('c++', [args.cxx], 'c++17')]:
        binary = directory / ('consumer-' + standard)
        run(compiler + ['-x', language, '-std=' + standard, '-Wall', '-Wextra', '-Werror'] +
            cflags + instrumentation + [str(args.source / 'tests/sdk-consumer.c'), '-o', str(binary)] +
            libs + ['-pthread'])
        runtime = dict(env, LD_LIBRARY_PATH=str(library.parent) + (
            os.pathsep + env['LD_LIBRARY_PATH'] if env.get('LD_LIBRARY_PATH') else ''))
        run([str(binary)], env=runtime, timeout=60)


def core_only(args, directory):
    build = directory / 'core-only'
    probes = directory / 'toolkit-probes'
    wrapper = directory / 'pkg-config'
    pkg_config = shutil.which('pkg-config')
    assert pkg_config
    # A separate configuration must succeed with service=false even if all auto
    # features and gcr are enabled. UI dependency probes are observable and fail.
    wrapper.write_text('#!/bin/sh\ncase "$*" in\n'
                       '  *gtk*|*adwaita*|*gcr*) printf "%s\\n" "$*" >> ' + shlex.quote(str(probes)) + '; exit 1;;\n'
                       'esac\nexec ' + shlex.quote(pkg_config) + ' "$@"\n')
    wrapper.chmod(0o755)
    env = dict(os.environ, PKG_CONFIG=str(wrapper))
    env.pop('PKG_CONFIG_SYSROOT_DIR', None)
    env.pop('PKG_CONFIG_PATH', None)
    run(['meson', 'setup', str(build), str(args.source), '--prefix=/usr', '--libdir=lib',
         '--wrap-mode=nofallback', '-Dservice=false', '--auto-features=enabled',
         '-Dgcr=enabled'], env=env)
    assert not probes.exists(), probes.read_text() if probes.exists() else ''
    deps = json.loads(output(['meson', 'introspect', '--dependencies', str(build)]))
    assert not any(re.search(r'gtk|adwaita|gcr', dep['name'], re.IGNORECASE) for dep in deps), deps
    run(['ninja', '-C', str(build), 'src/libxdp-certificate-core.so.0'])
    dest = directory / 'core-destdir'
    library, _, include = stage(build, dest)
    symbols(library, include)
    dependencies(library)
    installed = sorted(str(path.relative_to(dest)) for path in dest.rglob('*')
                       if path.is_file() or path.is_symlink())
    expected = sorted(['usr/lib/libxdp-certificate-core.so', 'usr/lib/libxdp-certificate-core.so.0',
                       'usr/lib/pkgconfig/xdp-certificate-core-0.pc'] +
                      ['usr/include/xdp-certificate-core-0/xdp-certificate/' + header for header in HEADERS])
    assert installed == expected, installed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['install', 'headers', 'symbols', 'core-only'])
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--cc-arg', action='append', required=True)
    parser.add_argument('--cxx', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='sdk-check-', dir=args.build) as temporary:
        directory = Path(temporary)
        if args.mode == 'core-only':
            core_only(args, directory)
            return
        library, env, include = stage(args.build, directory / 'destdir')
        if args.mode == 'symbols':
            symbols(library, include)
            dependencies(library)
        elif args.mode == 'headers':
            compile_headers(args, directory, include)
        else:
            consumers(args, directory, library, env)


if __name__ == '__main__':
    main()
