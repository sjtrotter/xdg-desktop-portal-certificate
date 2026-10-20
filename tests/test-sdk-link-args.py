#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Check SDK consumer link commands without invoking a compiler."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('sdk', Path(__file__).with_name('test-sdk.py'))
sdk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdk)


class ConsumerLinkArgs(unittest.TestCase):
    def consumer_calls(self, sanitizers, link_args):
        args = SimpleNamespace(cc_arg=['ccache', 'cc'], cxx='c++', source=Path('/source'),
                               build=Path('/build'))
        options = [{'name': 'b_sanitize', 'value': sanitizers},
                   {'name': 'c_link_args', 'value': link_args}]
        with patch.object(sdk, 'output', side_effect=[
                '-I/staged/include', '-L/staged/lib -lxdp-certificate-core', json.dumps(options)]), \
                patch.object(sdk, 'run') as run, \
                patch.dict(sdk.os.environ, {'LDFLAGS': ''}):
            sdk.consumers(args, Path('/tmp/consumers'), Path('/staged/lib/libcore.so'),
                          {'LD_LIBRARY_PATH': '/runtime/lib'})
        self.assertEqual(run.call_count, 4)
        self.assertEqual(run.call_args_list[0].args[0][:2], ['ccache', 'cc'])
        self.assertEqual(run.call_args_list[2].args[0][0], 'c++')
        for call in run.call_args_list[1::2]:
            self.assertEqual(call.kwargs['env']['LD_LIBRARY_PATH'], '/staged/lib:/runtime/lib')
        return [call.args[0] for call in run.call_args_list[::2]]

    def test_recorded_link_args_without_environment(self):
        for sanitizers in (['address', 'undefined'], 'address,undefined'):
            with self.subTest(sanitizers=sanitizers):
                commands = self.consumer_calls(sanitizers, ['-L/runtime with spaces/lib',
                                                           '-Wl,--as-needed'])
                for command in commands:
                    self.assertIn('-fsanitize=address,undefined', command)
                    self.assertEqual(command[-5:], ['-L/runtime with spaces/lib', '-Wl,--as-needed',
                                                    '-L/staged/lib', '-lxdp-certificate-core',
                                                    '-pthread'])

    def test_no_link_args_or_sanitizers(self):
        for sanitizers in ([], 'none'):
            with self.subTest(sanitizers=sanitizers):
                for command in self.consumer_calls(sanitizers, []):
                    self.assertFalse(any(arg.startswith('-fsanitize=') for arg in command))
                    self.assertEqual(command[-3:], ['-L/staged/lib', '-lxdp-certificate-core',
                                                    '-pthread'])


if __name__ == '__main__':
    unittest.main()
