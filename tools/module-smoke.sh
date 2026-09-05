#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
#
# module-smoke.sh -- the CLIENT-SIDE PKCS#11 MODULE, driven by three consumers
# that were never told about this project.
#
# The stack is tools/ui-smoke.sh's: a private bus inside a headless X server,
# the development frontend, this repository's backend, the SoftHSM fixture, and
# xdotool for the chooser and the PIN prompt. What is different is that nothing
# here speaks D-Bus. Everything talks PKCS#11 to
# build/src/module/libpkcs11-portal-certificate.so and the module does the
# talking:
#
#   0  p11tool --list-all-certs on a TOKEN-ONLY URI, and pkcs11-tool
#                                             --list-objects: two searches that
#                                             name no object, and NEITHER may
#                                             put a chooser up
#   1  p11tool --provider ... --list-all      GnuTLS enumerating the token, with
#                                             PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1
#   2  pkcs11-tool --sign                     one signature, verified with
#                                             openssl against the certificate
#                                             the module handed back
#   3  tests/gtls-client                      g_tls_certificate_new_from_pkcs11_uris()
#                                             plus a real mutual-TLS handshake
#                                             against a python server
#
# PHASE 0 IS THE ONE THAT CHANGED IN 2026-09. A chooser used to appear for any
# search whose CKA_CLASS this token has, which meant GnuTLS verifying a SERVER's
# certificate chain -- issuer and subject lookups issued across every p11-kit
# module on the machine -- raised one seconds after a sign-in window opened, for
# a certificate nobody had asked for. Only a search that names the object label,
# a CKA_ID or the private key acquires now; src/module/objects.c has the table.
# Phase 1 is an enumerating consumer and opts back in by hand, which is what
# PKCS11_PORTAL_CERTIFICATE_ENUMERATE is for and the only thing it is for.
#
# Phase 3 is the one that matters. It is docs/SPIKES.md S3 in its smallest
# honest form: the constructor WebKitGTK reaches through glib-networking has no
# module parameter, so the module has to be findable through p11-kit
# configuration alone.
#
# NOTHING IS INSTALLED SYSTEM WIDE. p11-kit reads user module files from
# $XDG_CONFIG_HOME/pkcs11/modules, so the run points XDG_CONFIG_HOME at a
# directory under $LOGDIR holding one .module file with an absolute path in it.
#
# WHAT IT NEEDS:
#
#   Xvfb, xdotool          as tools/ui-smoke.sh
#   a SoftHSM fixture      tools/softhsm-fixture.sh
#   a built frontend       as tools/dev-stack.sh describes
#   p11tool, pkcs11-tool, openssl, python3
#
#     tools/module-smoke.sh
#     tools/module-smoke.sh --phase 3        # just the handshake
#     tools/module-smoke.sh --phase 0        # just the "no chooser" proof

set -u

here() { cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd; }
REPO="$(here)"

BUILD="${BUILD:-$REPO/build}"
XDP_BUILD="${XDP_BUILD:-$REPO/../xdg-desktop-portal/build}"
BACKEND="${BACKEND:-$BUILD/src/xdg-desktop-portal-certificate}"
MODULE_SO="${MODULE_SO:-$BUILD/src/module/libpkcs11-portal-certificate.so}"
GTLS_CLIENT="${GTLS_CLIENT:-$BUILD/tests/gtls-client}"
XDP_ENV="${XDP_ENV:-$REPO/.xdp-env}"
SOFTHSM_DIR="${SOFTHSM_DIR:-${TMPDIR:-/tmp}/xdp-certificate-softhsm}"
XVFB="${XVFB:-$(command -v Xvfb || true)}"
XDOTOOL="${XDOTOOL:-$(command -v xdotool || true)}"
PIN="${PIN:-123456}"
CERT_LABEL="${CERT_LABEL:-Portal Certificate}"
# The URIs src/module/portal-token.h agrees with the web-auth backend. The
# object= is part of that contract now -- XDG_PORTAL_CERTIFICATE_CERT_URI and
# _KEY_URI carry it -- because a single-object import refuses a URI without one.
# $URI_OBJECT can be emptied to watch that refusal happen.
URI_TOKEN="pkcs11:model=portal-cert;manufacturer=freedesktop.org;token=Portal%20Certificate"
URI_OBJECT="${URI_OBJECT-;object=Portal%20Certificate}"
CERT_URI="${URI_TOKEN}${URI_OBJECT};type=cert"
KEY_URI="${URI_TOKEN}${URI_OBJECT};type=private"
SCREEN="${SCREEN:-:78}"
PHASES="${PHASES:-0 1 2 3}"

die() {
	echo "${0##*/}: $*" >&2
	exit 40
}

# shellcheck source=tools/lib.sh
. "$REPO/tools/lib.sh"

while [ $# -gt 0 ]; do
	case "$1" in
	--phase)
		PHASES="$2"
		shift 2
		;;
	*) break ;;
	esac
done

if [ -n "${LOGDIR:-}" ]; then
	fixture_make "$LOGDIR" module-smoke
else
	LOGDIR="$(fixture_mktemp xdp-certificate-module-smoke module-smoke)"
fi

[ -n "$XVFB" ] || die "Xvfb not found; set \$XVFB"
[ -n "$XDOTOOL" ] || die "xdotool not found; set \$XDOTOOL"
command -v p11tool >/dev/null || die "p11tool not found (gnutls-utils)"
command -v pkcs11-tool >/dev/null || die "pkcs11-tool not found (opensc)"
command -v openssl >/dev/null || die "openssl not found"
command -v python3 >/dev/null || die "python3 not found"
fixture_check "$SOFTHSM_DIR" softhsm
[ -f "$SOFTHSM_DIR/module-path" ] || die "no SoftHSM fixture; run tools/softhsm-fixture.sh"
[ -x "$BACKEND" ] || die "no backend at $BACKEND"
[ -f "$MODULE_SO" ] || die "no module at $MODULE_SO"
[ -x "$GTLS_CLIENT" ] || die "no gtls-client at $GTLS_CLIENT"
[ -x "$XDP_BUILD/desktop-portal/xdg-desktop-portal" ] || die "no frontend; set XDP_BUILD"

# shellcheck disable=SC1090
[ -f "$XDP_ENV" ] && . "$XDP_ENV"

DEVDIR="$LOGDIR/portals"
(umask 077 && mkdir -p "$DEVDIR")
xdp_write_portal_dir "$DEVDIR" "$REPO" private

# THE MODULE IS CONFIGURED FOR THIS RUN AND NOWHERE ELSE. `module:` is absolute
# here because the build tree is not p11-kit's module directory.
CONFDIR="$LOGDIR/config"
(umask 077 && mkdir -p "$CONFDIR/pkcs11/modules")
cat >"$CONFDIR/pkcs11/modules/xdg-desktop-portal-certificate.module" <<EOF
module: $MODULE_SO
critical: no
priority: -10
# MODULE_LOG_CALLS=1 makes p11-kit log every call into the module on the
# consumer's stderr, which is the only way to see what a TLS stack asked for
# before it gave up.
${MODULE_LOG_CALLS:+log-calls: yes}
EOF

"$XVFB" "$SCREEN" -screen 0 1280x1024x24 -nolisten tcp >"$LOGDIR/xvfb.log" 2>&1 &
XVFB_PID=$!
sleep 2

cleanup() {
	kill "$XVFB_PID" 2>/dev/null
	wait "$XVFB_PID" 2>/dev/null
}
trap cleanup EXIT

export DISPLAY="$SCREEN"
unset WAYLAND_DISPLAY
export GDK_BACKEND=x11
export GTK_A11Y=none
export SOFTHSM2_CONF="$SOFTHSM_DIR/softhsm2.conf"
export XDG_DESKTOP_PORTAL_DIR="$DEVDIR"
export XDG_CURRENT_DESKTOP="${XDG_CURRENT_DESKTOP:-dev}"
export XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate
export XDG_CONFIG_HOME="$CONFDIR"

# The RSA fixture, so that phase 2 can name one mechanism instead of guessing
# from whichever row the driver happened to select. A consumer that can use
# either key type leaves this unset and takes what the user picks.
export PKCS11_PORTAL_CERTIFICATE_KEY_ALGORITHMS=RSA
export PKCS11_PORTAL_CERTIFICATE_REASON="tools/module-smoke.sh"
export G_MESSAGES_DEBUG=pkcs11-portal-certificate

SOFTHSM_MODULE="$(cat "$SOFTHSM_DIR/module-path")"

cat >"$LOGDIR/tls-server.py" <<'PYTHON_EOF'
# A TLS server that REQUIRES a client certificate and checks it against the
# fixture's own certificate. It is deliberately not gnutls-serv: the fixture
# certificates are self-signed leaves without basicConstraints CA:TRUE, which
# GnuTLS will not accept as an anchor and OpenSSL will when it is the peer's own
# certificate in the trust store.
import socket, ssl, sys, threading

cert, key, ca, portfile = sys.argv[1:5]

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
context.load_verify_locations(ca)
context.verify_mode = ssl.CERT_REQUIRED

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen(1)
with open(portfile, "w") as handle:
    handle.write(str(listener.getsockname()[1]))
print("listening on", listener.getsockname()[1], flush=True)

listener.settimeout(180)
raw, address = listener.accept()
try:
    connection = context.wrap_socket(raw, server_side=True)
except Exception as error:
    print("FAIL: handshake:", error, flush=True)
    sys.exit(1)

peer = connection.getpeercert()
subject = dict(x[0] for x in peer["subject"])
print("client certificate:", subject, flush=True)
print("protocol:", connection.version(), "cipher:", connection.cipher()[0], flush=True)
connection.recv(64)
connection.sendall(b"PASS " + str(subject.get("commonName", "?")).encode() + b"\n")
try:
    connection.unwrap()
except Exception:
    pass
connection.close()
print("PASS", flush=True)
PYTHON_EOF

# THE PERSON AT THE KEYBOARD, IN A LOOP. Each phase is its own process and gets
# its own grant, so each puts up its own chooser and its own PIN prompt. The
# driver answers whatever appears until the run says it is finished.
cat >"$LOGDIR/driver.sh" <<'DRIVER_EOF'
#!/bin/bash
set -u
declare -A driven

press() {
	local wid="$1"
	shift
	"$XDOTOOL" windowfocus "$wid" 2>/dev/null
	sleep 1
	for key in "$@"; do
		case "$key" in
		type:) printf '%s' "$PIN" | "$XDOTOOL" type --delay 60 --file - ;;
		*) "$XDOTOOL" key "$key" ;;
		esac
		sleep 0.8
	done
}

# A window that is still there ten seconds after being answered was not
# answered: there is no window manager, so a focus set before the window was
# mapped goes nowhere and the keys land on nothing. The retry presses Return
# only, because Down has already moved the selection.
handle() {
	local wid="$1" now
	shift
	now="$(date +%s)"

	if [ -z "${driven[$wid]:-}" ]; then
		driven[$wid]="$now"
		echo "driver: $wid $*"
		press "$wid" "$@"
	elif [ $((now - driven[$wid])) -ge 10 ]; then
		driven[$wid]="$now"
		echo "driver: $wid still up, pressing Return again"
		press "$wid" Return
	fi
}

while [ ! -f "$LOGDIR/driver-stop" ]; do
	for wid in $("$XDOTOOL" search --onlyvisible --name "Use a Certificate" 2>/dev/null); do
		handle "$wid" Down Return
	done
	for wid in $("$XDOTOOL" search --onlyvisible --name "Unlock Security Token" 2>/dev/null); do
		handle "$wid" "type:" Return
	done
	sleep 1
done
DRIVER_EOF
chmod +x "$LOGDIR/driver.sh"

phase_wanted() {
	case " $PHASES " in
	*" $1 "*) return 0 ;;
	esac
	return 1
}

inner() {
	local rc=0

	"$XDP_BUILD/document-portal/xdg-permission-store" >"$LOGDIR/permission-store.log" 2>&1 &
	PERM=$!
	sleep 1

	"$XDP_BUILD/desktop-portal/xdg-desktop-portal" -v >"$LOGDIR/frontend.log" 2>&1 &
	FE=$!
	xdp_wait_for_name org.freedesktop.portal.Desktop "$FE" || {
		echo "module-smoke: the frontend never took org.freedesktop.portal.Desktop"
		tail -20 "$LOGDIR/frontend.log"
		return 40
	}

	"$BACKEND" --verbose --module "$SOFTHSM_MODULE" --allow-software-tokens \
		--pin-prompt gtk >"$LOGDIR/backend.log" 2>&1 &
	BE=$!
	xdp_wait_for_name org.freedesktop.impl.portal.desktop.certificate "$BE" || {
		echo "module-smoke: the backend never took its bus name"
		tail -20 "$LOGDIR/backend.log"
		return 40
	}

	rm -f "$LOGDIR/driver-stop"
	"$LOGDIR/driver.sh" >"$LOGDIR/driver.log" 2>&1 &
	DRIVER=$!

	# THE COUNT IS THE PROOF. A grant is a chooser the user answered, so the
	# question "did that search put a window up" is answered by how many
	# grant-created lines the backend wrote, not by whether the command
	# succeeded -- both of these are expected to succeed and find nothing.
	grants_created() {
		grep -c 'grant-created' "$LOGDIR/backend.log" 2>/dev/null || true
	}

	if phase_wanted 0; then
		local before after
		echo
		echo "=== 0  a search that names no object must not ask for one ==="
		before="$(grants_created)"

		timeout 180 p11tool --provider "$MODULE_SO" --list-all-certs "$URI_TOKEN" \
			>"$LOGDIR/quiet-p11tool.log" 2>&1
		timeout 180 pkcs11-tool --module "$MODULE_SO" --list-objects \
			>"$LOGDIR/quiet-pkcs11-tool.log" 2>&1

		after="$(grants_created)"
		echo "grants before=$before after=$after"

		if [ "$before" != "$after" ]; then
			echo "module-smoke: an enumeration raised a chooser"
			grep -E 'grant-created|chooser-shown' "$LOGDIR/backend.log" | tail -5
			rc=1
		elif grep -qE '^\s*Object [0-9]+:' "$LOGDIR/quiet-p11tool.log"; then
			echo "module-smoke: p11tool got objects out of an unacquired token"
			cat "$LOGDIR/quiet-p11tool.log"
			rc=1
		else
			echo "module-smoke: neither search acquired a credential"
		fi
	fi

	if phase_wanted 1 && [ "$rc" = 0 ]; then
		echo
		echo "=== 1  p11tool --list-all through the module ==="
		# The opt-in, and the only place in this repository that sets it: this
		# is a consumer that names no object because it is asking what is there.
		if PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1 timeout 180 \
			p11tool --provider "$MODULE_SO" --list-all \
			>"$LOGDIR/p11tool.log" 2>&1; then
			grep -E "Object |Type:|Label:|URL:" "$LOGDIR/p11tool.log" | head -20
			grep -q "Private key" "$LOGDIR/p11tool.log" || {
				echo "module-smoke: p11tool found no private key"
				rc=1
			}
		else
			echo "module-smoke: p11tool failed"
			tail -20 "$LOGDIR/p11tool.log"
			rc=1
		fi
	fi

	if phase_wanted 2 && [ "$rc" = 0 ]; then
		echo
		echo "=== 2  pkcs11-tool --sign, verified with openssl ==="
		printf 'the quick brown fox' >"$LOGDIR/data"

		# pkcs11-tool will not read an object without being told which, and
		# neither will GnuTLS: CKA_LABEL is a constant for exactly that reason.
		timeout 180 pkcs11-tool --module "$MODULE_SO" --login --read-object --type cert \
			--label "$CERT_LABEL" \
			--output-file "$LOGDIR/cert.der" >"$LOGDIR/read-object.log" 2>&1

		if [ ! -s "$LOGDIR/cert.der" ]; then
			echo "module-smoke: could not read the certificate back"
			tail -20 "$LOGDIR/read-object.log"
			rc=1
		elif ! timeout 180 pkcs11-tool --module "$MODULE_SO" --login --sign \
			--mechanism SHA256-RSA-PKCS --label "$CERT_LABEL" \
			--input-file "$LOGDIR/data" \
			--output-file "$LOGDIR/sig" >"$LOGDIR/sign.log" 2>&1; then
			echo "module-smoke: pkcs11-tool --sign failed"
			tail -20 "$LOGDIR/sign.log"
			rc=1
		else
			openssl x509 -inform der -in "$LOGDIR/cert.der" -pubkey -noout \
				-out "$LOGDIR/pub.pem" 2>/dev/null
			openssl x509 -inform der -in "$LOGDIR/cert.der" -noout -subject
			if openssl dgst -sha256 -verify "$LOGDIR/pub.pem" \
				-signature "$LOGDIR/sig" "$LOGDIR/data"; then
				echo "module-smoke: the signature verifies against the certificate the module returned"
			else
				echo "module-smoke: the signature DID NOT verify"
				rc=1
			fi
		fi
	fi

	if phase_wanted 3 && [ "$rc" = 0 ]; then
		echo
		echo "=== 3  g_tls_certificate_new_from_pkcs11_uris + mutual TLS ==="

		# A throwaway server certificate. What is under test is the CLIENT's,
		# and tests/gtls-client.c accepts any server certificate for that
		# reason.
		openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
			-keyout "$LOGDIR/server.key" -out "$LOGDIR/server.pem" >/dev/null 2>&1

		python3 "$LOGDIR/tls-server.py" "$LOGDIR/server.pem" "$LOGDIR/server.key" \
			"$SOFTHSM_DIR/portal-test-rsa.pem" "$LOGDIR/port" >"$LOGDIR/server.log" 2>&1 &
		SERVER=$!

		for _ in $(seq 1 40); do
			[ -s "$LOGDIR/port" ] && break
			sleep 0.25
		done
		PORT="$(cat "$LOGDIR/port" 2>/dev/null)"

		if [ -z "$PORT" ]; then
			echo "module-smoke: the TLS server did not start"
			cat "$LOGDIR/server.log"
			rc=1
		elif timeout 180 "$GTLS_CLIENT" \
			"$CERT_URI" "$KEY_URI" \
			127.0.0.1 "$PORT" >"$LOGDIR/gtls-client.log" 2>&1; then
			cat "$LOGDIR/gtls-client.log"
			grep -E "client certificate|protocol|PASS" "$LOGDIR/server.log"
		else
			echo "module-smoke: the mutual-TLS handshake did not complete"
			cat "$LOGDIR/gtls-client.log"
			cat "$LOGDIR/server.log"
			rc=1
		fi

		kill "$SERVER" 2>/dev/null
	fi

	touch "$LOGDIR/driver-stop"
	kill "$DRIVER" "$FE" "$BE" "$PERM" 2>/dev/null

	return "$rc"
}

export PIN LOGDIR REPO XDP_BUILD BACKEND MODULE_SO GTLS_CLIENT XDOTOOL SOFTHSM_MODULE \
	SOFTHSM_DIR PHASES CERT_LABEL CERT_URI KEY_URI URI_TOKEN
dbus-run-session -- bash -c \
	"$(declare -f xdp_wait_for_name); $(declare -f phase_wanted); $(declare -f inner); inner"
rc=$?

echo
if [ "$rc" = 0 ]; then
	echo "module-smoke: PASS; logs in $LOGDIR"
else
	echo "module-smoke: FAIL ($rc); logs in $LOGDIR"
fi
exit "$rc"
