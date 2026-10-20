#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
"""Exercise tool failures with fake D-Bus, timers and external commands."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parent.parent


class BusError(Exception):
    @property
    def message(self):
        return str(self)


def load_e2e():
    gi = types.ModuleType("gi")
    gi.require_version = lambda *_: None
    repository = types.ModuleType("gi.repository")
    repository.GLib = types.SimpleNamespace(Error=BusError, SOURCE_REMOVE=False)
    repository.Gio = types.SimpleNamespace(
        DBusCallFlags=types.SimpleNamespace(NONE=0),
        DBusSignalFlags=types.SimpleNamespace(NONE=0),
    )
    spec = importlib.util.spec_from_file_location("certificate_e2e", REPO / "tools/certificate-e2e.py")
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, {"gi": gi, "gi.repository": repository}):
        spec.loader.exec_module(module)
    return module


E2E = load_e2e()


class Timers:
    def __init__(self):
        self.now = 0
        self.counter = 0
        self.sources = {}
        self.running = False

    def add(self, delay, callback):
        self.counter += 1
        self.sources[self.counter] = (self.now + delay, callback)
        return self.counter

    def remove(self, source):
        del self.sources[source]

    def run(self):
        self.running = True
        while self.running:
            source = min(self.sources, key=lambda key: self.sources[key][0])
            self.now, callback = self.sources.pop(source)
            callback()

    def quit(self):
        self.running = False


class Bus:
    def __init__(self, close_error):
        self.close_error = close_error
        self.closes = 0
        self.callback = None

    def get_unique_name(self):
        return ":1.42"

    def signal_subscribe(self, _sender, _iface, _signal, _path, _arg, _flags, callback, _data):
        self.callback = callback
        return 1

    def signal_unsubscribe(self, subscription):
        self.callback = None

    def call_sync(self, _name, _path, _iface, method, *_args):
        assert method == "Close"
        self.closes += 1
        if self.close_error:
            raise BusError("Close refused")


class E2ETests(unittest.TestCase):
    def drive(self, response_at=None, response=1, close_error=False, through_main=False):
        timers = Timers()
        bus = Bus(close_error)
        portal = E2E.Portal.__new__(E2E.Portal)
        portal.bus = bus
        portal.timeout = 5000
        portal.counter = 0
        portal.close_delivered = False

        def call(_method, _parameters, _reply_type):
            path = E2E.request_path(bus, f"c{os.getpid()}_{portal.counter}")
            if response_at is not None:
                timers.add(response_at, lambda: bus.callback(
                    None, None, path, None, None, (response, {})))
            return types.SimpleNamespace(unpack=lambda: (path,))

        portal.call = call
        self.portal = portal
        self.output = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(self.output))
            stack.enter_context(contextlib.redirect_stderr(self.output))
            stack.enter_context(mock.patch.object(E2E.GLib, "MainLoop", lambda: timers, create=True))
            stack.enter_context(mock.patch.object(E2E.GLib, "timeout_add", timers.add, create=True))
            stack.enter_context(mock.patch.object(E2E.GLib, "source_remove", timers.remove, create=True))
            if not through_main:
                return portal.request("AcquireCredential", lambda _: None, "c", 100)
            stack.enter_context(mock.patch.object(E2E, "Portal", return_value=portal))
            stack.enter_context(mock.patch.object(E2E, "check_exported"))
            stack.enter_context(mock.patch.object(E2E, "show_capabilities", return_value={}))
            stack.enter_context(mock.patch.object(E2E, "create_session", return_value="/session"))
            stack.enter_context(mock.patch.object(E2E, "release"))
            stack.enter_context(mock.patch.object(E2E, "acquire", side_effect=lambda *_:
                portal.request("AcquireCredential", lambda _: None, "c", 100)))
            return E2E.main(["certificate-e2e.py", "--cancel-after", "100", "--expect-cancelled"])

    def test_close_without_response(self):
        self.assertEqual(self.drive(through_main=True), E2E.EXIT_PASS)
        self.assertTrue(self.portal.close_delivered)
        self.assertEqual(self.portal.bus.closes, 1)
        self.assertIn("Close() delivered, no Response", self.output.getvalue())

    def test_cancel_response_after_close(self):
        self.assertEqual(self.drive(110, 1, through_main=True), E2E.EXIT_PASS)
        self.assertTrue(self.portal.close_delivered)

    def test_responses_before_close_fail(self):
        for response in (0, 1, 2):
            with self.subTest(response=response), self.assertRaises(SystemExit) as error:
                self.drive(10, response, through_main=True)
            self.assertEqual(error.exception.code, E2E.EXIT_FAIL)
            self.assertEqual(self.portal.bus.closes, 0)
            self.assertNotIn("PASS cancel", self.output.getvalue())

    def test_unrelated_responses_after_close_fail(self):
        for response in (0, 2):
            with self.subTest(response=response), self.assertRaises(SystemExit) as error:
                self.drive(110, response, through_main=True)
            self.assertEqual(error.exception.code, E2E.EXIT_FAIL)
            self.assertNotIn("PASS cancel", self.output.getvalue())

    def test_failed_close_fails(self):
        with self.assertRaisesRegex(RuntimeError, "Request.Close failed"):
            self.drive(close_error=True, through_main=True)
        self.assertFalse(self.portal.close_delivered)
        self.assertNotIn("Close() delivered", self.output.getvalue())

    def test_close_state_resets_between_requests(self):
        self.drive()
        self.assertTrue(self.portal.close_delivered)
        with mock.patch.object(E2E.GLib, "MainLoop", side_effect=RuntimeError("stop"), create=True):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                self.portal.request("Sign", lambda _: None, "s")
        self.assertFalse(self.portal.close_delivered)

    def test_usage_errors_exit_64(self):
        for arguments in (["--unknown"], ["--lifetime", "invalid"], ["--purpose", "invalid"],
                          ["--expect-cancelled"], ["--expect-cancelled", "--cancel-after", "-1"],
                          ["--expect-cancelled", "--cancel-after", "100",
                           "--expect-user-cancelled", "chooser"]):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    E2E.parse_args(arguments)
                self.assertEqual(error.exception.code, E2E.EXIT_USAGE)

    def test_help_exits_zero(self):
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as error:
            E2E.parse_args(["--help"])
        self.assertEqual(error.exception.code, 0)


class ShellTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "calls"
        self.env = dict(os.environ, HOME=str(self.root), PATH=f"{self.bin}:{os.environ['PATH']}",
                        TEST_CALLS=str(self.calls))
        self.command("gdbus", 'printf "%s\\n" "$*" >>"$TEST_CALLS"\n'
                     'echo "interface org.freedesktop.portal.experimental.Certificate1"\n')

    def command(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/bash\n" + body)
        path.chmod(0o755)

    def run_tool(self, name, *args):
        return subprocess.run(["bash", str(REPO / "tools" / name), *args], env=self.env,
                              capture_output=True, text=True, timeout=10)

    def test_trigger_inspects_without_sessions(self):
        result = self.run_tool("trigger-certificate.sh", "all")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls.read_text().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertIn("Properties.Get", calls[0])
        self.assertIn("GetCapabilities", calls[1])

    def test_trigger_rejects_session_commands(self):
        for command in ("session", "acquire", "sign", "release", "monitor"):
            with self.subTest(command=command):
                result = self.run_tool("trigger-certificate.sh", command, "/session")
                self.assertEqual(result.returncode, 64, result.stderr)
                self.assertIn("certificate-e2e.py", result.stderr)
        self.assertFalse(self.calls.exists())

    def test_trigger_stops_on_inspection_failure(self):
        self.command("gdbus", 'echo failed >>"$TEST_CALLS"\nexit 1\n')
        result = self.run_tool("trigger-certificate.sh", "all")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.calls.read_text().splitlines(), ["failed"])

    def firefox(self):
        self.command("flatpak", 'case "$*" in\n'
                     '  info*) exit 0;;\n'
                     '  *--command=sh*) exit 1;;\n'
                     '  *--command=gdbus*) echo "org.freedesktop.portal.experimental.Certificate1";;\n'
                     '  *) echo firefox-launched >>"$TEST_CALLS";;\nesac\n')
        module = self.root / "alternate-name.so"
        module.write_bytes(b"test module")
        return self.run_tool("firefox-flatpak.sh", "--module", str(module))

    def test_firefox_copies_to_advertised_name(self):
        result = self.firefox()
        self.assertEqual(result.returncode, 0, result.stderr)
        installed = self.root / ".var/app/org.mozilla.firefox/data/libpkcs11-portal-certificate.so"
        self.assertEqual(installed.read_bytes(), b"test module")
        self.assertIn(str(installed), result.stdout)
        self.assertIn("firefox-launched", self.calls.read_text())

    def test_firefox_stops_on_copy_failure(self):
        self.command("cp", "exit 1\n")
        result = self.firefox()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("module could not be copied", result.stderr)
        self.assertNotIn("firefox-launched", self.calls.read_text())

    def test_firefox_stops_on_directory_failure(self):
        self.command("mkdir", "exit 1\n")
        result = self.firefox()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("module directory could not be created", result.stderr)
        self.assertNotIn("firefox-launched", self.calls.read_text())


if __name__ == "__main__":
    unittest.main()
