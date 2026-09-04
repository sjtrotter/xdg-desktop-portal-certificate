#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# certificate-e2e.py -- drive the PUBLIC Certificate portal interface end to
# end, the way an application would, and check that what comes back verifies.
#
# THIS TALKS TO THE FRONTEND, NEVER TO THIS REPOSITORY'S BACKEND. Everything
# below goes to org.freedesktop.portal.experimental.Certificate on
# org.freedesktop.portal.Desktop at /org/freedesktop/portal/desktop. An
# application would do exactly this, and it is the only way to exercise the
# backend the way it is meant to be exercised: through the frontend's app id
# derivation, option validation, lifetime ceiling, grant table and results
# clamping.
#
#     CreateSession -> AcquireCredential -> Sign -> verify the signature with
#     the certificate that came back
#
# and, with --decrypt, the other direction: encrypt to the public key in the
# certificate the portal returned, with RSA-OAEP, and check that Decrypt gives
# the plaintext back. RSA_OAEP is the only mechanism Decrypt takes; PKCS#1 v1.5
# decryption is refused on both sides of the boundary because its outcome is an
# oracle over the card's key.
#
# The interface only exists if the running xdg-desktop-portal was started with
#     XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate
# (or "all"). With the gate off, this says so and exits 40 rather than dumping a
# D-Bus traceback: that is the gate working, not a bug.
#
# Exit codes match the backend's:
#     0  PASS                  40 unavailable (no portal, gate off, no token)
#     1  FAIL (a check failed)  2 cancelled or refused by the user
#    64  usage                 70 internal error
#
# Run it through tools/dev-stack.sh, which puts a development frontend and this
# repository's backend on a private bus first. docs/TESTING.md has the commands
# for a run against a real card.

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
IFACE = "org.freedesktop.portal.experimental.Certificate"
REQUEST_IFACE = "org.freedesktop.portal.Request"

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_CANCELLED = 2
EXIT_UNAVAILABLE = 40
EXIT_USAGE = 64
EXIT_INTERNAL = 70

# The portal names its Request objects after the caller's unique bus name, with
# the leading ':' dropped and '.' turned into '_'. Knowing the path in advance
# is what lets this script subscribe BEFORE the call is made; the Response can
# otherwise arrive before the method has returned.
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
        """org.freedesktop.portal.Request.Close on an in-flight request. This is
        what an application does when the user gives up on it, and the frontend
        forwards it to the backend's own Request object."""
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
        except GLib.Error as error:
            print(f"note: Close said {error.message}", file=sys.stderr)

    def request(self, method, build_parameters, prefix, cancel_after=0):
        """Make a Request call and wait for its single Response signal."""
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
                # The portal is entitled to choose its own path; follow it
                # rather than waiting forever on the one we guessed.
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

            def on_timeout():
                answer["timeout"] = True
                loop.quit()
                return GLib.SOURCE_REMOVE

            source = GLib.timeout_add(self.timeout, on_timeout)

            cancel_source = None
            if cancel_after > 0:
                def do_close():
                    print(f"closing {returned} after {cancel_after} ms")
                    self.close_request(returned)

                    # UPSTREAM UNEXPORTS THE FRONTEND REQUEST BEFORE FORWARDING
                    # Close() to the backend, so no Response signal follows a
                    # Close: the application asked, so it already knows. The
                    # grace period below is there to catch a backend that
                    # answers anyway with a grant, which would mean the window
                    # was never torn down.
                    def give_up():
                        answer["closed"] = True
                        loop.quit()
                        return GLib.SOURCE_REMOVE

                    GLib.timeout_add(2000, give_up)
                    return GLib.SOURCE_REMOVE

                cancel_source = GLib.timeout_add(cancel_after, do_close)

            loop.run()

            if cancel_source is not None:
                GLib.source_remove(cancel_source)
            if not answer.get("timeout"):
                GLib.source_remove(source)
        finally:
            self.bus.signal_unsubscribe(subscription)

        if answer.get("timeout"):
            raise TimeoutError(f"{method} produced no Response within {self.timeout} ms")

        if answer.get("closed"):
            return None, {}

        return answer["response"], answer["results"]


def die(status, message):
    print(f"FAIL: {message}" if status == EXIT_FAIL else message, file=sys.stderr)
    sys.exit(status)


def check_gate(portal):
    """Is the experimental interface exported at all?"""
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
            f"{IFACE} is not exported.\n"
            "The portal must be started with "
            "XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate (or 'all'), and "
            "it must be the branch experimental/certificate-webauthentication.\n"
            "With the gate off the interface is absent from introspection; that "
            "is the gate working, not a bug.\n"
            f"D-Bus said: {error.message}",
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

    return results.get("session_handle", path)


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


def acquire(portal, session, args):
    def options(handle):
        values = {
            "handle_token": GLib.Variant("s", handle),
            "purpose": GLib.Variant("s", args.purpose),
            "reason": GLib.Variant("s", args.reason),
            "requested_lifetime": GLib.Variant("u", args.lifetime),
            "interaction_mode": GLib.Variant("s", args.interaction_mode),
            "allow_selection_memory": GLib.Variant("b", args.remember),
        }
        if args.decrypt:
            # The default is {'sign': true}, so a grant that may decrypt has to
            # be asked for. The backend intersects this with the key's own
            # CKA_DECRYPT, and the frontend intersects the answer again.
            values["operation_policy"] = GLib.Variant(
                "a{sv}",
                {"sign": GLib.Variant("b", True), "decrypt": GLib.Variant("b", True)},
            )
        filter_options = build_filter(args)
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


def decrypt(portal, session, args, ciphertext):
    def options(handle):
        parameters = {"hash": GLib.Variant("s", args.oaep_hash)}
        if args.oaep_label:
            parameters["label"] = GLib.Variant("ay", args.oaep_label.encode())

        values = {
            "handle_token": GLib.Variant("s", handle),
            "mechanism": GLib.Variant("s", "RSA_OAEP"),
            "operation_id": GLib.Variant("s", "e2e-decrypt-1"),
            "parameters": GLib.Variant("a{sv}", parameters),
            "ciphertext": GLib.Variant("ay", ciphertext),
        }
        return GLib.Variant("(osa{sv})", (session, args.parent_window, values))

    return portal.request("Decrypt", options, "c")


def oaep_encrypt_with_cryptography(cert_der, plaintext, hash_name, label):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    algorithm = getattr(hashes, hash_name.replace("-", ""))()
    public_key = x509.load_der_x509_certificate(cert_der).public_key()

    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=algorithm),
            algorithm=algorithm,
            label=label,
        ),
    )


def oaep_encrypt_with_openssl(cert_der, plaintext, hash_name, label):
    with tempfile.TemporaryDirectory() as directory:
        cert_path = os.path.join(directory, "certificate.der")
        pubkey_path = os.path.join(directory, "public.pem")
        plain_path = os.path.join(directory, "plaintext.bin")
        cipher_path = os.path.join(directory, "ciphertext.bin")

        with open(cert_path, "wb") as handle:
            handle.write(cert_der)
        with open(plain_path, "wb") as handle:
            handle.write(plaintext)

        subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-in", cert_path,
             "-pubkey", "-noout", "-out", pubkey_path],
            check=True, capture_output=True,
        )

        digest = hash_name.replace("-", "").lower()
        command = [
            "openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", pubkey_path,
            "-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", f"rsa_oaep_md:{digest}",
            "-pkeyopt", f"rsa_mgf1_md:{digest}",
        ]
        if label:
            command += ["-pkeyopt", "rsa_oaep_label:" + label.hex()]
        command += ["-in", plain_path, "-out", cipher_path]

        subprocess.run(command, check=True, capture_output=True)

        with open(cipher_path, "rb") as handle:
            return handle.read()


def oaep_encrypt(cert_der, plaintext, hash_name, label):
    """Encrypt with something that is not this backend.

    If the two ever disagree about how OAEP is spelled, the round trip has to
    fail rather than agree with itself, so the ciphertext comes from python
    cryptography or, failing that, from openssl(1).
    """
    try:
        return oaep_encrypt_with_cryptography(cert_der, plaintext, hash_name, label)
    except ImportError:
        return oaep_encrypt_with_openssl(cert_der, plaintext, hash_name, label)


def run_decrypt(portal, session, args, cert_der, operations):
    if "decrypt" not in operations:
        die(EXIT_FAIL,
            f"the grant does not permit decryption; it permits {operations}. The key's "
            "CKA_DECRYPT, or the certificate's key usage, may not allow it")

    plaintext = f"e2e session key {time.time()}".encode()
    label = args.oaep_label.encode() if args.oaep_label else None

    try:
        ciphertext = oaep_encrypt(cert_der, plaintext, args.oaep_hash, label)
    except Exception as error:
        die(EXIT_UNAVAILABLE, f"could not encrypt with RSA-OAEP: {error}")

    print(f"\nencrypted {len(plaintext)} bytes to the certificate's key, "
          f"RSA-OAEP/{args.oaep_hash}"
          + (f", label {args.oaep_label!r}" if args.oaep_label else "")
          + f" -> {len(ciphertext)} bytes")

    response, results = decrypt(portal, session, args, ciphertext)

    if response == 1:
        print("Decrypt was cancelled by the user.")
        return EXIT_CANCELLED
    if response != 0:
        die(EXIT_FAIL,
            f"Decrypt answered {response}: {dict(results)}. A token that only implements "
            "OAEP with SHA-1 -- SoftHSM 2.x does -- needs --oaep-hash SHA1 and no label")

    recovered = bytes(results["plaintext"])
    if recovered != plaintext:
        die(EXIT_FAIL,
            f"the plaintext did not survive the round trip: {recovered!r} != {plaintext!r}")

    print(f"decrypted {len(recovered)} bytes, operation_id={results.get('operation_id')}")
    print("verified  the plaintext came back byte for byte")
    return EXIT_PASS


def release(portal, session):
    try:
        portal.call("ReleaseGrant", GLib.Variant("(o)", (session,)), None)
    except GLib.Error as error:
        print(f"note: ReleaseGrant said {error.message}", file=sys.stderr)


# ----------------------------------------------------------------- verifying


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
            # PKCS#11 produces the raw r||s pair; X.509 wants an
            # ECDSA-Sig-Value. See docs/IMPL-INTERFACE.md.
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
        print("note: python-cryptography not importable; falling back to openssl",
              file=sys.stderr)
        return verify_with_openssl(cert_der, signature, message, mechanism, hash_name, der)

    return verify_with_cryptography(cert_der, signature, message, mechanism, hash_name, der)


# ---------------------------------------------------------------------- main


def parse_args(argv):
    parser = argparse.ArgumentParser(
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
                        help="ask for a DER ECDSA-Sig-Value instead of raw r||s")
    parser.add_argument("--remember", action="store_true",
                        help="pass allow_selection_memory and tick the box if offered")
    parser.add_argument("--decrypt", action="store_true",
                        help="ask for a grant that may decrypt, then encrypt to the "
                        "certificate's key with RSA-OAEP and check that Decrypt gives the "
                        "plaintext back")
    parser.add_argument("--decrypt-only", action="store_true",
                        help="with --decrypt, skip the Sign half")
    parser.add_argument("--oaep-hash", default="SHA256",
                        choices=["SHA1", "SHA256", "SHA384", "SHA512"],
                        help="OAEP hash and MGF1 hash. SoftHSM 2.x implements SHA1 only")
    parser.add_argument("--oaep-label", help="OAEP label, as text. SoftHSM 2.x refuses any")
    parser.add_argument("--timeout", type=int, default=180000,
                        help="milliseconds to wait for each Response (default 180000)")
    parser.add_argument("--capabilities", action="store_true",
                        help="print GetCapabilities and exit")
    parser.add_argument("--close", action="store_true",
                        help="acquire a grant, release it, and exit without signing")
    parser.add_argument("--cancel-after", type=int, default=0, metavar="MS",
                        help="call Request.Close() on the AcquireCredential request after this "
                        "many milliseconds; the chooser must close and the response must be 1 "
                        "or 2, never a grant")
    parser.add_argument("--expect-cancelled", action="store_true",
                        help="PASS when AcquireCredential comes back cancelled rather than with "
                        "a grant; use it with --cancel-after")
    parser.add_argument("--expect-no-certificate", action="store_true",
                        help="PASS when AcquireCredential fails cleanly with no token or no "
                        "matching certificate; this is the no-card plumbing check")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv[1:])

    try:
        portal = Portal(args.timeout)
    except GLib.Error as error:
        die(EXIT_UNAVAILABLE, f"no session bus: {error.message}")

    check_gate(portal)

    capabilities = show_capabilities(portal)
    if args.capabilities:
        return EXIT_PASS

    print()
    session = create_session(portal)
    print(f"session   {session}")

    response, results = acquire(portal, session, args)

    if args.expect_cancelled:
        if response == 0:
            die(EXIT_FAIL, "expected a cancellation, but a grant was issued")
        if response is None:
            print("\nClose() returned and no Response followed it, which is what upstream's "
                  "Request does: it unexports before forwarding the Close.")
        else:
            print(f"\nAcquireCredential answered {response} after Close().")
        print("PASS (the frontend's Close() reached the backend; check the backend log for "
              "chooser-cancelled)")
        return EXIT_PASS

    if args.expect_no_certificate:
        # THE NO-CARD PLUMBING CHECK. The point is that the frontend routed to
        # this backend, the backend answered, and the answer was a clean refusal
        # rather than a hang or a crash.
        if response == 0:
            die(EXIT_FAIL, "expected no certificate, but a grant was issued")
        print(f"\nAcquireCredential answered {response} with no grant, as expected.")
        print("PASS (plumbing: the frontend reached the backend and the backend refused "
              "cleanly)")
        return EXIT_PASS

    if response is None:
        die(EXIT_FAIL, "the request was closed and produced no grant")
    if response == 1:
        print("\nAcquireCredential was cancelled by the user.")
        return EXIT_CANCELLED
    if response != 0:
        die(
            EXIT_UNAVAILABLE,
            f"AcquireCredential answered {response}. With no card in a reader, or no "
            "certificate matching the purpose, that is the expected answer; run with "
            "--expect-no-certificate to assert it.",
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

    print(f"\ngrant     {results.get('grant_id')}")
    print(f"subject   {subject}")
    print(f"key       {key_type} {results.get('key_size')} {results.get('key_curve', '')}".rstrip())
    print(f"chain     {results.get('chain_status')}")
    print(f"token     {dict(results.get('token_display', {}))}")
    print(f"mechs     {mechanisms}")
    print(f"ops       {operations}")
    print(f"expires   {results.get('expires_at')}")
    print(f"prompts   may_prompt_later={results.get('may_prompt_later')}")

    if args.close:
        release(portal, session)
        print("\nPASS (grant acquired and released; no signature was requested)")
        return EXIT_PASS

    if args.decrypt and args.decrypt_only:
        status = run_decrypt(portal, session, args, cert_der, operations)
        release(portal, session)
        if status != EXIT_PASS:
            return status
        print("\nPASS")
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
        print("Sign was cancelled by the user.")
        release(portal, session)
        return EXIT_CANCELLED
    if response != 0:
        release(portal, session)
        die(EXIT_FAIL, f"Sign answered {response}")

    signature = bytes(results["signature"])
    print(f"signature {len(signature)} bytes, operation_id={results.get('operation_id')}")

    try:
        verify(cert_der, signature, message, mechanism, args.hash_name, args.der)
    except Exception as error:
        release(portal, session)
        die(EXIT_FAIL, f"the signature did not verify against the certificate: {error}")

    print("verified  the signature checks out against the certificate the portal returned")

    if args.decrypt:
        status = run_decrypt(portal, session, args, cert_der, operations)
        if status != EXIT_PASS:
            release(portal, session)
            return status

    release(portal, session)

    print("\nPASS")
    return EXIT_PASS


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        sys.exit(EXIT_CANCELLED)
    except TimeoutError as timeout:
        print(f"FAIL: {timeout}", file=sys.stderr)
        sys.exit(EXIT_FAIL)
    except GLib.Error as dbus_error:
        print(f"D-Bus error: {dbus_error.message}", file=sys.stderr)
        sys.exit(EXIT_INTERNAL)
