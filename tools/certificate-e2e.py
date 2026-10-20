#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
# Drive the public Certificate1 interface and verify signatures; see docs/TESTING.md for setup and exit codes.

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time

import gi

gi.require_version("GLib", "2.0")
gi.require_version("Gio", "2.0")
from gi.repository import GLib, Gio  # noqa: E402

BUS_NAME = "org.freedesktop.portal.Desktop"
OBJECT_PATH = "/org/freedesktop/portal/desktop"
IFACE = "org.freedesktop.portal.experimental.Certificate1"
REQUEST_IFACE = "org.freedesktop.portal.Request"

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_CANCELLED = 2
EXIT_UNAVAILABLE = 40
EXIT_USAGE = 64
EXIT_INTERNAL = 70

# Subscribe at the predicted Request path before calling because Response may precede the method reply.
def request_path(connection, token):
    sender = connection.get_unique_name()[1:].replace(".", "_")
    return f"{OBJECT_PATH}/request/{sender}/{token}"


def session_path(connection, token):
    sender = connection.get_unique_name()[1:].replace(".", "_")
    return f"{OBJECT_PATH}/session/{sender}/{token}"


class Portal:
    def __init__(self, timeout):
        self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.timeout = timeout
        self.counter = 0
        self.close_delivered = False

    def token(self, prefix):
        self.counter += 1
        return f"{prefix}{os.getpid()}_{self.counter}"

    def call(self, method, parameters, reply_type):
        return self.bus.call_sync(
            BUS_NAME,
            OBJECT_PATH,
            IFACE,
            method,
            parameters,
            reply_type,
            Gio.DBusCallFlags.NONE,
            self.timeout,
            None,
        )

    def close_request(self, path):
        try:
            self.bus.call_sync(
                BUS_NAME,
                path,
                REQUEST_IFACE,
                "Close",
                None,
                None,
                Gio.DBusCallFlags.NONE,
                5000,
                None,
            )
            return True
        except GLib.Error as error:
            print(f"Request.Close failed: {error.message}", file=sys.stderr)
            return False

    def request(self, method, build_parameters, prefix, cancel_after=0):
        self.close_delivered = False
        handle_token = self.token(prefix)
        path = request_path(self.bus, handle_token)

        loop = GLib.MainLoop()
        answer = {}

        def on_response(_conn, _sender, _path, _iface, _signal, params, *_user_data):
            answer["response"] = params[0]
            answer["results"] = params[1]
            loop.quit()

        subscription = self.bus.signal_subscribe(
            None,
            REQUEST_IFACE,
            "Response",
            path,
            None,
            Gio.DBusSignalFlags.NONE,
            on_response,
            None,
        )

        try:
            reply = self.call(method, build_parameters(handle_token), None)
            returned = reply.unpack()[0]
            if returned != path:
                # The portal may return a different Request path from the prediction.
                self.bus.signal_unsubscribe(subscription)
                subscription = self.bus.signal_subscribe(
                    None,
                    REQUEST_IFACE,
                    "Response",
                    returned,
                    None,
                    Gio.DBusSignalFlags.NONE,
                    on_response,
                    None,
                )

            # Callbacks clear their source IDs; cleanup removes only live sources.
            live = {"timeout": 0, "cancel": 0, "give_up": 0}

            def on_timeout():
                live["timeout"] = 0
                answer["timeout"] = True
                loop.quit()
                return GLib.SOURCE_REMOVE

            live["timeout"] = GLib.timeout_add(self.timeout, on_timeout)

            if cancel_after > 0:
                def do_close():
                    live["cancel"] = 0
                    print(f"closing {returned} after {cancel_after} ms")
                    if not self.close_request(returned):
                        answer["close_failed"] = True
                        loop.quit()
                        return GLib.SOURCE_REMOVE
                    self.close_delivered = True

                    # Frontend Close() unexports before forwarding, so the grace period checks that no late grant arrives.
                    def give_up():
                        live["give_up"] = 0
                        answer["closed"] = True
                        loop.quit()
                        return GLib.SOURCE_REMOVE

                    live["give_up"] = GLib.timeout_add(2000, give_up)
                    return GLib.SOURCE_REMOVE

                live["cancel"] = GLib.timeout_add(cancel_after, do_close)

            loop.run()

            for name in ("timeout", "cancel", "give_up"):
                if live[name] != 0:
                    GLib.source_remove(live[name])
                    live[name] = 0
        finally:
            self.bus.signal_unsubscribe(subscription)

        if answer.get("timeout"):
            raise TimeoutError(f"{method} produced no Response within {self.timeout} ms")

        if answer.get("close_failed"):
            raise RuntimeError(f"{method}: Request.Close failed")

        if answer.get("closed"):
            return None, {}

        return answer["response"], answer["results"]


def die(status, message):
    print(f"FAIL: {message}" if status == EXIT_FAIL else message, file=sys.stderr)
    sys.exit(status)


def check_exported(portal):
    try:
        portal.bus.call_sync(
            BUS_NAME,
            OBJECT_PATH,
            "org.freedesktop.DBus.Properties",
            "Get",
            GLib.Variant("(ss)", (IFACE, "version")),
            GLib.VariantType("(v)"),
            Gio.DBusCallFlags.NONE,
            5000,
            None,
        )
    except GLib.Error as error:
        if "ServiceUnknown" in error.message or "was not provided" in error.message:
            die(
                EXIT_UNAVAILABLE,
                "No xdg-desktop-portal on this bus.\n"
                "Run this through tools/dev-stack.sh, or start the development "
                "frontend first.",
            )
        die(
            EXIT_UNAVAILABLE,
            f"{IFACE} is not exported on {OBJECT_PATH}.\n"
            "Use frontend branch experimental/certificate with a configured certificate backend "
            "and XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=Certificate1 in its environment.\n"
            f"D-Bus error: {error.message}",
        )


def show_capabilities(portal):
    reply = portal.call(
        "GetCapabilities", GLib.Variant("(a{sv})", ({},)), GLib.VariantType("(a{sv})")
    )
    capabilities = reply.unpack()[0]

    print("GetCapabilities:")
    for key in sorted(capabilities):
        print(f"  {key:32} {capabilities[key]}")

    return capabilities


def create_session(portal):
    session_token = portal.token("s")
    path = session_path(portal.bus, session_token)

    response, results = portal.request(
        "CreateSession",
        lambda handle: GLib.Variant(
            "(a{sv})",
            (
                {
                    "handle_token": GLib.Variant("s", handle),
                    "session_handle_token": GLib.Variant("s", session_token),
                },
            ),
        ),
        "c",
    )

    if response != 0:
        die(EXIT_UNAVAILABLE, f"CreateSession answered {response}")

    # Compare the returned session handle against the prediction; its wire type is an object path.
    handle = results.get("session_handle")
    if handle is None:
        die(EXIT_UNAVAILABLE, "CreateSession returned no session_handle")
    if handle != path:
        print(f"note: session handle {handle} is not the predicted {path}", file=sys.stderr)

    return handle


def build_filter(args):
    filter_options = {}
    if args.token_label:
        filter_options["token_label"] = GLib.Variant("s", args.token_label)
    if args.piv_slot:
        filter_options["piv_slot"] = GLib.Variant("s", args.piv_slot)
    if args.key_algorithm:
        filter_options["key_algorithms"] = GLib.Variant("as", [args.key_algorithm])
    if args.eku:
        filter_options["eku"] = GLib.Variant("as", [args.eku])
    return filter_options


def acquire(portal, session, args, key_algorithm=None):
    def options(handle):
        values = {
            "handle_token": GLib.Variant("s", handle),
            "purpose": GLib.Variant("s", args.purpose),
            "reason": GLib.Variant("s", args.reason),
            "requested_lifetime": GLib.Variant("u", args.lifetime),
            "interaction_mode": GLib.Variant("s", args.interaction_mode),
        }
        filter_options = build_filter(args)
        if key_algorithm:
            filter_options["key_algorithms"] = GLib.Variant("as", [key_algorithm])
        if filter_options:
            values["certificate_filter"] = GLib.Variant("a{sv}", filter_options)
        return GLib.Variant("(osa{sv})", (session, args.parent_window, values))

    return portal.request("AcquireCredential", options, "c", args.cancel_after)


def sign(portal, session, args, mechanism, digest, hash_name):
    def options(handle):
        parameters = {"hash": GLib.Variant("s", hash_name)}
        if args.der and mechanism == "ECDSA":
            parameters["signature_encoding"] = GLib.Variant("s", "der")

        values = {
            "handle_token": GLib.Variant("s", handle),
            "mechanism": GLib.Variant("s", mechanism),
            "operation_id": GLib.Variant("s", "e2e-1"),
            "parameters": GLib.Variant("a{sv}", parameters),
            "data": GLib.Variant("ay", digest),
        }
        return GLib.Variant("(osa{sv})", (session, args.parent_window, values))

    return portal.request("Sign", options, "c")


def release(portal, session):
    try:
        portal.bus.call_sync(
            BUS_NAME, session, "org.freedesktop.portal.Session", "Close",
            None, None, Gio.DBusCallFlags.NONE, portal.timeout, None,
        )
    except GLib.Error as error:
        print(f"Session.Close failed: {error.message}", file=sys.stderr)




def verify_with_cryptography(cert_der, signature, message, mechanism, hash_name, der):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

    certificate = x509.load_der_x509_certificate(cert_der)
    public_key = certificate.public_key()
    algorithm = {"SHA256": hashes.SHA256(), "SHA384": hashes.SHA384(), "SHA512": hashes.SHA512()}[
        hash_name
    ]

    if mechanism == "ECDSA":
        if not der:
            # Convert PKCS#11 r||s to DER ECDSA-Sig-Value for verification.
            half = len(signature) // 2
            r = int.from_bytes(signature[:half], "big")
            s = int.from_bytes(signature[half:], "big")
            signature = utils.encode_dss_signature(r, s)
        public_key.verify(signature, message, ec.ECDSA(algorithm))
    elif mechanism == "RSA_PKCS1_V1_5":
        public_key.verify(signature, message, padding.PKCS1v15(), algorithm)
    elif mechanism == "RSA_PSS":
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(algorithm), salt_length=algorithm.digest_size),
            algorithm,
        )
    else:
        raise ValueError(f"cannot verify {mechanism}")

    return True


def verify_with_openssl(cert_der, signature, message, mechanism, hash_name, der):
    if shutil.which("openssl") is None:
        raise RuntimeError("neither python-cryptography nor openssl is available")

    with tempfile.TemporaryDirectory() as directory:
        cert_path = os.path.join(directory, "cert.der")
        pub_path = os.path.join(directory, "pub.pem")
        sig_path = os.path.join(directory, "sig.bin")
        msg_path = os.path.join(directory, "msg.bin")

        with open(cert_path, "wb") as handle:
            handle.write(cert_der)
        with open(sig_path, "wb") as handle:
            handle.write(signature)
        with open(msg_path, "wb") as handle:
            handle.write(message)

        subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-in", cert_path, "-pubkey", "-noout",
             "-out", pub_path],
            check=True,
        )

        if mechanism == "ECDSA" and not der:
            raise RuntimeError(
                "the openssl fallback cannot verify a raw r||s ECDSA signature; "
                "pass --der, or install python-cryptography"
            )

        command = [
            "openssl", "dgst", f"-{hash_name.lower()}", "-verify", pub_path,
            "-signature", sig_path,
        ]
        if mechanism == "RSA_PSS":
            command += ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:-1"]
        command.append(msg_path)

        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stdout.strip() or result.stderr.strip())

    return True


def verify(cert_der, signature, message, mechanism, hash_name, der):
    try:
        import cryptography  # noqa: F401
    except ImportError:
        print("python-cryptography unavailable; using openssl",
              file=sys.stderr)
        return verify_with_openssl(cert_der, signature, message, mechanism, hash_name, der)

    return verify_with_cryptography(cert_der, signature, message, mechanism, hash_name, der)




class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def parse_args(argv):
    parser = ArgumentParser(
        description="Drive the experimental Certificate portal end to end.",
        epilog="Exit codes: 0 PASS, 1 FAIL, 2 cancelled, 40 unavailable, 64 usage, "
        "70 internal.",
    )
    parser.add_argument("--purpose", default="client_auth",
                        choices=["client_auth", "signing", "email", "ssh"])
    parser.add_argument("--reason", default="End-to-end test of the Certificate portal")
    parser.add_argument("--lifetime", type=int, default=300)
    parser.add_argument("--interaction-mode", default="allowed",
                        choices=["required", "allowed", "forbidden"])
    parser.add_argument("--parent-window", default="",
                        help="portal window identifier, e.g. wayland:<handle>")
    parser.add_argument("--token-label", help="certificate_filter.token_label")
    parser.add_argument("--piv-slot", help="certificate_filter.piv_slot")
    parser.add_argument("--key-algorithm", help="certificate_filter.key_algorithms entry")
    parser.add_argument("--eku", help="certificate_filter.eku entry, an OID")
    parser.add_argument("--hash", dest="hash_name", default="SHA256",
                        choices=["SHA256", "SHA384", "SHA512"])
    parser.add_argument("--mechanism", help="override the mechanism chosen from the key type")
    parser.add_argument("--der", action="store_true",
                        help="request DER ECDSA-Sig-Value encoding")
    parser.add_argument("--timeout", type=int, default=180000,
                        help="milliseconds to wait for each Response (default 180000)")
    parser.add_argument("--capabilities", action="store_true",
                        help="print GetCapabilities and exit")
    parser.add_argument("--close", action="store_true",
                        help="acquire a grant, release it, and exit without signing")
    parser.add_argument("--cancel-after", type=int, default=0, metavar="MS",
                        help="close AcquireCredential after this many milliseconds and check for no grant")
    expectations = parser.add_mutually_exclusive_group()
    expectations.add_argument("--expect-cancelled", action="store_true",
                              help="require successful Request.Close and no grant; use with --cancel-after")
    expectations.add_argument("--expect-user-cancelled", choices=["chooser", "pin"],
                              help="require user cancellation (response 1) at this dialog")
    parser.add_argument("--regrant", metavar="KEY_ALGORITHM",
                        help="acquire on a second session with this key algorithm and verify its signature")
    expectations.add_argument("--expect-no-certificate", action="store_true",
                              help="pass if acquisition fails without a grant")
    args = parser.parse_args(argv)
    if args.expect_cancelled and args.cancel_after <= 0:
        parser.error("--expect-cancelled requires --cancel-after greater than zero")
    return args


def main(argv):
    args = parse_args(argv[1:])

    try:
        portal = Portal(args.timeout)
    except GLib.Error as error:
        die(EXIT_UNAVAILABLE, f"no session bus: {error.message}")

    check_exported(portal)

    capabilities = show_capabilities(portal)
    if args.capabilities:
        return EXIT_PASS

    print()
    session = create_session(portal)
    print(f"session   {session}")

    response, results = acquire(portal, session, args)

    if args.expect_user_cancelled == "chooser":
        if response != 1:
            release(portal, session)
            die(EXIT_FAIL, f"expected chooser cancellation (1), got {response}")
        print("PASS cancel: chooser answered 1, no grant")
        release(portal, session)
        return EXIT_PASS

    if args.expect_cancelled:
        # Frontend Close() unexports the Request before forwarding, so no Response follows.
        if not portal.close_delivered:
            die(EXIT_FAIL, f"acquisition ended before Request.Close succeeded (Response {response})")
        if response == 0:
            die(EXIT_FAIL, "expected a cancellation, but a grant was issued")
        if response not in (None, 1):
            die(EXIT_FAIL, f"expected cancellation (1) or no Response, got {response}")
        if response is None:
            print("PASS cancel: Close() delivered, no Response")
        else:
            print(f"PASS cancel: Close() delivered, Response {response}")
        return EXIT_PASS

    if args.expect_no_certificate:
        if response == 0:
            die(EXIT_FAIL, "expected no certificate, but a grant was issued")
        print(f"PASS no-certificate: AcquireCredential answered {response}, no grant")
        return EXIT_PASS

    if response is None:
        die(EXIT_FAIL, "the request was closed and produced no grant")
    if response == 1:
        print("cancelled by the user")
        return EXIT_CANCELLED
    if response != 0:
        die(
            EXIT_UNAVAILABLE,
            f"AcquireCredential failed with response {response}; use --expect-no-certificate to check acquisition failure.",
        )

    cert_der = bytes(results["certificate_der"])
    key_type = results.get("key_type", "unknown")
    mechanisms = list(results.get("supported_mechanisms", []))
    operations = list(results.get("permitted_operations", []))

    subject = "(could not parse)"
    try:
        from cryptography import x509

        subject = x509.load_der_x509_certificate(cert_der).subject.rfc4514_string()
    except Exception:
        pass

    print(f"\nsubject   {subject}")
    print(f"key       {key_type} {results.get('key_size')} {results.get('key_curve', '')}".rstrip())
    print(f"chain     {results.get('chain_status')}")
    print(f"token     {dict(results.get('token_display', {}))}")
    print(f"mechs     {mechanisms}")
    print(f"ops       {operations}")
    print(f"expires   {results.get('expires_at')}")
    print(f"prompts   may_prompt_later={results.get('may_prompt_later')}")

    if args.close:
        release(portal, session)
        print("PASS grant: acquired and released, no signature requested")
        return EXIT_PASS

    mechanism = args.mechanism
    if mechanism is None:
        mechanism = "ECDSA" if key_type == "EC" else "RSA_PKCS1_V1_5"
    if mechanism not in mechanisms:
        die(EXIT_FAIL, f"the grant does not offer {mechanism}; it offers {mechanisms}")

    message = f"xdg-desktop-portal-certificate e2e {time.time()}".encode()
    digest = hashlib.new(args.hash_name.lower(), message).digest()

    print(f"\nsigning   {len(message)} bytes, {args.hash_name} digest, {mechanism}")
    response, results = sign(portal, session, args, mechanism, digest, args.hash_name)

    if response == 1:
        print("cancelled by the user")
        release(portal, session)
        if args.expect_user_cancelled == "pin":
            print("PASS cancel: PIN dialog answered 1, no signature")
            return EXIT_PASS
        return EXIT_CANCELLED
    if response != 0:
        release(portal, session)
        die(EXIT_FAIL, f"Sign answered {response}")

    if args.expect_user_cancelled:
        release(portal, session)
        die(EXIT_FAIL, "expected user cancellation, but Sign succeeded")

    signature = bytes(results["signature"])
    print(f"signature {len(signature)} bytes, operation_id={results.get('operation_id')}")

    try:
        verify(cert_der, signature, message, mechanism, args.hash_name, args.der)
    except Exception as error:
        release(portal, session)
        die(EXIT_FAIL, f"the signature did not verify against the certificate: {error}")

    print("verified  signature checks against the returned certificate")

    if args.regrant:
        status = run_regrant(portal, args, cert_der)
        if status != EXIT_PASS:
            release(portal, session)
            return status

    release(portal, session)

    print("PASS")
    return EXIT_PASS


def run_regrant(portal, args, first_cert_der):
    session = create_session(portal)
    print(f"\nre-grant  a second session {session}, filtered to {args.regrant}")

    response, results = acquire(portal, session, args, key_algorithm=args.regrant)

    if response != 0:
        die(EXIT_FAIL, f"the second AcquireCredential answered {response}")

    cert_der = bytes(results["certificate_der"])
    key_type = results.get("key_type", "unknown")
    mechanisms = list(results.get("supported_mechanisms", []))

    print(f"re-grant  key {key_type}, {len(cert_der)} certificate bytes")

    # Use the returned certificate; certificate_id is confined to the impl interface.
    if cert_der == first_cert_der:
        die(EXIT_FAIL,
            "Second grant returned the first certificate; choose a different --regrant key algorithm")

    mechanism = "ECDSA" if key_type == "EC" else "RSA_PKCS1_V1_5"
    if mechanism not in mechanisms:
        die(EXIT_FAIL, f"the re-grant does not offer {mechanism}; it offers {mechanisms}")

    message = f"xdg-desktop-portal-certificate e2e re-grant {time.time()}".encode()
    digest = hashlib.new(args.hash_name.lower(), message).digest()

    print(f"re-grant  signing with {mechanism}")
    response, results = sign(portal, session, args, mechanism, digest, args.hash_name)

    if response != 0:
        die(EXIT_FAIL, f"Sign after the re-grant answered {response}")

    signature = bytes(results["signature"])

    try:
        verify(cert_der, signature, message, mechanism, args.hash_name, args.der)
    except Exception as error:
        die(EXIT_FAIL,
            f"Second signature verification failed against the returned certificate: {error}")

    print("re-grant  verified against the new certificate")
    release(portal, session)
    return EXIT_PASS


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        sys.exit(EXIT_CANCELLED)
    except (TimeoutError, RuntimeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(EXIT_FAIL)
    except GLib.Error as dbus_error:
        print(f"D-Bus error: {dbus_error.message}", file=sys.stderr)
        sys.exit(EXIT_INTERNAL)
