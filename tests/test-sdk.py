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

# Independent original UI layouts. Freeze every old offset and the exact order
# of each append-only extension in both C and C++, including alignment padding.
UI_LAYOUTS = (
    ('XccChooserCandidateView', 'ChooserCandidate', '''
    uint32_t struct_size, abi_version;
    uint64_t id;
    const char *subject, *issuer, *token, *reader, *expiry, *detail, *fingerprint;
    bool invalid;
''', ('struct_size', 'abi_version', 'id', 'subject', 'issuer', 'token', 'reader',
      'expiry', 'detail', 'fingerprint', 'invalid'), '''
    XCC_ALIGNAS(8) int64_t not_before;
    int64_t not_after;
    uint32_t validity;
    const char *key_type;
    uint32_t key_size, display_flags;
''', ('not_before', 'not_after', 'validity', 'key_type', 'key_size', 'display_flags'),
     'XCC_CHOOSER_CANDIDATE_VIEW_V1_SIZE'),
    ('XccChooserView', 'Chooser', '''
    uint32_t struct_size, abi_version;
    uint64_t revision;
    const XccChooserCandidateView *candidates;
    size_t n_candidates;
    const char *caller_name, *app_id;
    XccIdentityLevel identity_level;
    const char *identity_detail;
    XccPurpose purpose;
    const char *purpose_text, *purpose_detail;
    bool may_sign, may_decrypt;
    const char *operation_scope;
    uint32_t lifetime_seconds;
    const char *duration, *later_prompt, *reason_label, *untrusted_reason;
    bool tokens_present;
    const char *parent_window, *activation_token;
''', ('struct_size', 'abi_version', 'revision', 'candidates', 'n_candidates',
      'caller_name', 'app_id', 'identity_level', 'identity_detail', 'purpose',
      'purpose_text', 'purpose_detail', 'may_sign', 'may_decrypt', 'operation_scope',
      'lifetime_seconds', 'duration', 'later_prompt', 'reason_label', 'untrusted_reason',
      'tokens_present', 'parent_window', 'activation_token'), '''
    XCC_ALIGNAS(8) bool generic_purpose;
    uint32_t display_flags;
''', ('generic_purpose', 'display_flags'), 'XCC_CHOOSER_VIEW_V1_SIZE'),
    ('XccPinView', 'Pin', '''
    uint32_t struct_size, abi_version;
    const char *token_label, *reader, *caller_display, *purpose_display, *parent_window;
    bool context_specific, protected_path, busy, count_low, final_try, locked;
    const char *status;
''', ('struct_size', 'abi_version', 'token_label', 'reader', 'caller_display',
      'purpose_display', 'parent_window', 'context_specific', 'protected_path', 'busy',
      'count_low', 'final_try', 'locked', 'status'), '''
    XCC_ALIGNAS(8) uint32_t purpose;
    bool generic_purpose;
    uint32_t status_code, display_flags;
''', ('purpose', 'generic_purpose', 'status_code', 'display_flags'), 'XCC_PIN_VIEW_V1_SIZE'),
    ('XccWarning', 'Warning', '''
    uint32_t struct_size, abi_version;
    XccWarningCode code;
    uint64_t warning_id;
    const char *message;
''', ('struct_size', 'abi_version', 'code', 'warning_id', 'message'), '', (), None),
)


def ui_layout_assertions(assertion):
    source = ''
    for struct, name, prefix, fields, extension, appended, minimum in UI_LAYOUTS:
        source += f'typedef struct {{{prefix}}} {name}Prefix;\n'
        for field in fields:
            source += (f'{assertion}(offsetof({struct}, {field}) == '
                       f'offsetof({name}Prefix, {field}), "UI prefix: {struct}.{field}");\n')
        if minimum:
            source += (f'{assertion}({minimum} == sizeof({name}Prefix), "UI minimum: {struct}");\n'
                       f'{assertion}(offsetof({struct}, {appended[0]}) >= {minimum}, '
                       f'"extension outside V1 padding: {struct}");\n'
                       f'typedef struct {{ {name}Prefix prefix; {extension} }} {name}Extended;\n')
            for field in appended:
                source += (f'{assertion}(offsetof({struct}, {field}) == '
                           f'offsetof({name}Extended, {field}), "UI extension: {struct}.{field}");\n')
        else:
            source += f'{assertion}(sizeof({struct}) == sizeof({name}Prefix), "UI size: {struct}");\n'
    source += (f'{assertion}(XCC_VALIDITY_VALID == 0 && XCC_VALIDITY_EXPIRED == 1 && '
               'XCC_VALIDITY_NOT_YET_VALID == 2 && XCC_VALIDITY_UNKNOWN == 3, "validity values");\n')
    source += (f'{assertion}(XCC_PIN_STATUS_NONE == 0 && XCC_PIN_STATUS_INCORRECT == 1 && '
               'XCC_PIN_STATUS_REQUIRED == 2 && XCC_PIN_STATUS_TOO_LONG == 3 && '
               'XCC_PIN_STATUS_MEMORY_UNAVAILABLE == 4, "PIN status values");\n')
    return source


def ilp32_layout_assertions(assertion):
    # Fixed-width pointer/size surrogates let a native compiler check the layout
    # arithmetic even without multilib headers. Model both i386 and ARM EABI's
    # uint64_t alignment. The real headers are also compiled with -m32 if usable.
    source = 'typedef struct { uint32_t words[4]; } ModelBytes32;\n'
    candidate_prefix = CANDIDATE_PREFIX.split('{', 1)[1].split('}', 1)[0]
    layouts = [(name, prefix, extension, appended[0], fields[-1], 48 if name == 'ChooserCandidate' else
                40 if name == 'Pin' else None)
               for _, name, prefix, fields, extension, appended, minimum in UI_LAYOUTS if minimum]
    layouts.append(('CandidateInfo', candidate_prefix,
                    'XCC_ALIGNAS(8) const char *token_label;', 'token_label', 'protected_path', None))
    for alignment in (4, 8):
        integer = f'ModelU64A{alignment}'
        source += (f'typedef struct {{ XCC_ALIGNAS({alignment}) uint32_t words[2]; }} {integer};\n'
                   f'{assertion}(XCC_ALIGNOF({integer}) == {alignment}, "model integer alignment");\n')
        for name, prefix, extension, first, last, size in layouts:
            def model_fields(fields):
                fields = re.sub(r'const char\s*\*const\s*\*', 'uint32_t ', fields)
                fields = re.sub(r'const (?:char|XccChooserCandidateView)\s*\*', 'uint32_t ', fields)
                fields = fields.replace('*', '')  # Remaining comma-separated pointer declarators.
                fields = re.sub(r'\b(?:size_t|XccIdentityLevel|XccPurpose)\b', 'uint32_t', fields)
                fields = fields.replace('XccBytes', 'ModelBytes32')
                return re.sub(r'\b(?:u?int64_t)\b', integer, fields)
            original = f'{name}32A{alignment}Prefix'
            extended = f'{name}32A{alignment}Extended'
            if name == 'Chooser':
                size = 92 if alignment == 4 else 96
            elif name == 'CandidateInfo':
                size = 80 if alignment == 4 else 88
            offset = (size + 7) // 8 * 8
            original_alignment = 'uint32_t' if name == 'Pin' else integer
            source += (f'typedef struct {{ {model_fields(prefix)} }} {original};\n'
                       f'typedef struct {{ {model_fields(prefix + extension)} }} {extended};\n'
                       f'{assertion}(sizeof({original}) == {size}, "ILP32 original size: {original}");\n'
                       f'{assertion}(XCC_PADDED_SIZE(offsetof({original}, {last}) + '
                       f'sizeof((({original} *)0)->{last}), XCC_MAX_ALIGNOF({original_alignment}, uint32_t)) '
                       f'== sizeof({original}), "ILP32 padded minimum: {original}");\n'
                       f'{assertion}(offsetof({extended}, {first}) == {offset}, '
                       f'"ILP32 extension offset: {extended}");\n'
                       f'{assertion}(offsetof({extended}, {first}) >= sizeof({original}), '
                       f'"ILP32 extension outside original padding: {extended}");\n')
    return source


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
                for index, field in enumerate(TOKEN_FIELDS)) +
            f'{assertion}(offsetof(XccCandidateInfo, token_label) >= sizeof(CandidatePrefix), '
            '"token extension outside V1 padding");\n' + ui_layout_assertions(assertion) +
            ilp32_layout_assertions(assertion))
        run(compiler + ['-x', language, '-std=' + standard, '-Wall', '-Wextra', '-Werror',
                        '-I' + str(include), '-fsyntax-only', str(source)])
        # Probe standard headers separately so an ABI assertion failure cannot
        # accidentally be treated as an unavailable 32-bit toolchain.
        probe = directory / ('probe32.' + ('cc' if language == 'c++' else 'c'))
        probe.write_text('#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n')
        for abi_flags in (['-m32'], ['-m32', '-malign-double']):
            flags = compiler + abi_flags + ['-x', language, '-std=' + standard]
            available = subprocess.run(flags + ['-fsyntax-only', str(probe)], text=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if available.returncode == 0:
                run(flags + ['-Wall', '-Wextra', '-Werror', '-I' + str(include),
                             '-fsyntax-only', str(source)])
            else:
                print(f'{language} {shlex.join(abi_flags)} unavailable; native header compilation '
                      'includes static ILP32 models with 4- and 8-byte uint64_t alignment.\n' +
                      available.stderr, flush=True)


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
