#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
# Exercise the client module through PKCS#11 consumers; see docs/TESTING.md for prerequisites and phases.

set -u

here() { cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd; }
REPO="$(here)"

BUILD="${BUILD:-$REPO/build}"
XDP_BUILD="${XDP_BUILD:-$REPO/../xdg-desktop-portal/build}"
MODULE_SO="${MODULE_SO:-$BUILD/src/module/libpkcs11-portal-certificate.so}"
GTLS_CLIENT="${GTLS_CLIENT:-$BUILD/tests/gtls-client}"
XDP_ENV="${XDP_ENV:-$REPO/.xdp-env}"
SOFTHSM_DIR="${SOFTHSM_DIR:-${TMPDIR:-/tmp}/xdp-certificate-softhsm}"
XVFB="${XVFB:-$(command -v Xvfb || true)}"
XDOTOOL="${XDOTOOL:-$(command -v xdotool || true)}"
PIN="${PIN:-123456}"
CERT_LABEL="${CERT_LABEL:-Portal Certificate}"
# Single-object imports require object=; these URIs follow src/module/portal-token.h.
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
xdp_smoke_select_backend "$BUILD/src/xdg-desktop-portal-certificate"

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
xdp_smoke_prepare "$LOGDIR" "$REPO" "$SOFTHSM_DIR"

# The build-tree module needs an absolute path in the run's private p11-kit configuration.
# A distinct file name: p11-kit merges same-named files, and an installed
# xdg-desktop-portal-certificate.module would lend its enable-in list, excluding gtls-client.
CONFDIR="$LOGDIR/config"
(umask 077 && mkdir -p "$CONFDIR/pkcs11/modules")
cat >"$CONFDIR/pkcs11/modules/portal-certificate-smoke.module" <<EOF
module: $MODULE_SO
critical: no
priority: -10
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
export XDG_CONFIG_HOME="$CONFDIR"

# Select the RSA fixture so phase 2 can name its signing mechanism.
export PKCS11_PORTAL_CERTIFICATE_KEY_ALGORITHMS=RSA
export PKCS11_PORTAL_CERTIFICATE_REASON="tools/module-smoke.sh"
export G_MESSAGES_DEBUG=pkcs11-portal-certificate

SOFTHSM_MODULE="$(cat "$SOFTHSM_DIR/module-path")"

cat >"$LOGDIR/tls-server.py" <<'PYTHON_EOF'
# OpenSSL accepts the fixture's self-signed leaf as a peer trust anchor; GnuTLS requires CA constraints.
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

# Without a window manager, focus may precede mapping; retry Return without moving the selection again.
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
	for wid in $("$XDOTOOL" search --onlyvisible --name "$CHOOSER_TITLE" 2>/dev/null); do
		handle "$wid" Down Return
	done
	for wid in $("$XDOTOOL" search --onlyvisible --name "$PIN_TITLE" 2>/dev/null); do
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
	. "$REPO/tools/lib.sh"
	if [ "$BACKEND_KIND" = kde ]; then
		xdp_smoke_start_kde_backend || return 40
	fi

	"$XDP_BUILD/document-portal/xdg-permission-store" >"$LOGDIR/permission-store.log" 2>&1 &
	PERM=$!
	sleep 1

	XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL="$(xdp_experimental_portals Certificate1)" \
	"$XDP_BUILD/desktop-portal/xdg-desktop-portal" -v >"$LOGDIR/frontend.log" 2>&1 &
	FE=$!
	xdp_wait_for_name org.freedesktop.portal.Desktop "$FE" || {
		echo "module-smoke: the frontend never took org.freedesktop.portal.Desktop"
		tail -20 "$LOGDIR/frontend.log"
		return 40
	}

	if [ "$BACKEND_KIND" = gtk ]; then
		"$BACKEND" --verbose --module "$SOFTHSM_MODULE" --allow-software-tokens \
			--pin-prompt gtk >"$LOGDIR/backend.log" 2>&1 &
		BE=$!
		xdp_wait_for_name org.freedesktop.impl.portal.desktop.certificate "$BE" || {
			echo "module-smoke: the backend never took its bus name"
			tail -20 "$LOGDIR/backend.log"
			return 40
		}
	fi

	rm -f "$LOGDIR/driver-stop"
	"$LOGDIR/driver.sh" >"$LOGDIR/driver.log" 2>&1 &
	DRIVER=$!

	# Count grants because successful empty searches must not open a chooser.
	grants_created() {
		grep -c 'grant-created' "$LOGDIR/backend.log" 2>/dev/null || true
	}

	if phase_wanted 0; then
		local before after
		echo
		echo "=== 0  unnamed searches do not acquire credentials ==="
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

		# Single-object imports require the constant CKA_LABEL.
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
				echo "module-smoke: Signature verification failed"
				rc=1
			fi
		fi
	fi

	if phase_wanted 3 && [ "$rc" = 0 ]; then
		echo
		echo "=== 3  g_tls_certificate_new_from_pkcs11_uris + mutual TLS ==="

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
xdp_smoke_run_session bash -c \
	"$(declare -f xdp_experimental_portals); $(declare -f xdp_wait_for_name); $(declare -f phase_wanted); $(declare -f inner); inner"
rc=$?

echo
if [ "$rc" = 0 ]; then
	echo "module-smoke: PASS; logs in $LOGDIR"
else
	echo "module-smoke: FAIL ($rc); logs in $LOGDIR"
fi
exit "$rc"
