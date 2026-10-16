#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
# NSS consumer setup and phase expectations are documented in docs/TESTING.md.

set -u

here() { cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd; }
REPO="$(here)"

BUILD="${BUILD:-$REPO/build}"
XDP_BUILD="${XDP_BUILD:-$REPO/../xdg-desktop-portal/build}"
BACKEND="${BACKEND:-$BUILD/src/xdg-desktop-portal-certificate}"
MODULE_SO="${MODULE_SO:-$BUILD/src/module/libpkcs11-portal-certificate.so}"
XDP_ENV="${XDP_ENV:-$REPO/.xdp-env}"
SOFTHSM_DIR="${SOFTHSM_DIR:-${TMPDIR:-/tmp}/xdp-certificate-softhsm}"
XVFB="${XVFB:-$(command -v Xvfb || true)}"
XDOTOOL="${XDOTOOL:-$(command -v xdotool || true)}"
NSS_BIN="${NSS_BIN:-}"
PIN="${PIN:-123456}"
TOKEN_LABEL="${TOKEN_LABEL:-Portal Certificate}"
CERT_LABEL="${CERT_LABEL:-Portal Certificate}"
SCREEN="${SCREEN:-:77}"
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
	fixture_make "$LOGDIR" nss-smoke
else
	LOGDIR="$(fixture_mktemp xdp-certificate-nss-smoke nss-smoke)"
fi

find_nss_tool() {
	local name="$1" candidate

	if [ -n "$NSS_BIN" ] && [ -x "$NSS_BIN/$name" ]; then
		echo "$NSS_BIN/$name"
		return
	fi

	if command -v "$name" >/dev/null; then
		command -v "$name"
		return
	fi

	for candidate in "${NSS_BIN:+${NSS_BIN%/bin}/lib64/nss/unsupported-tools/$name}" \
		/usr/lib64/nss/unsupported-tools/"$name" \
		/usr/lib/nss/unsupported-tools/"$name"; do
		[ -n "$candidate" ] && [ -x "$candidate" ] && {
			echo "$candidate"
			return
		}
	done

	die "$name not found (nss-tools). Install it, or unpack the rpm and set
\$NSS_BIN to its /usr/bin; nothing here needs the package installed."
}

CERTUTIL="${CERTUTIL:-$(find_nss_tool certutil)}" || exit 40
MODUTIL="${MODUTIL:-$(find_nss_tool modutil)}" || exit 40
TSTCLNT="${TSTCLNT:-$(find_nss_tool tstclnt)}" || exit 40

[ -n "$XVFB" ] || die "Xvfb not found; set \$XVFB"
[ -n "$XDOTOOL" ] || die "xdotool not found; set \$XDOTOOL"
command -v openssl >/dev/null || die "openssl not found"
command -v python3 >/dev/null || die "python3 not found"
fixture_check "$SOFTHSM_DIR" softhsm
[ -f "$SOFTHSM_DIR/module-path" ] || die "no SoftHSM fixture; run tools/softhsm-fixture.sh"
[ -x "$BACKEND" ] || die "no backend at $BACKEND"
[ -f "$MODULE_SO" ] || die "no module at $MODULE_SO"
[ -x "$XDP_BUILD/desktop-portal/xdg-desktop-portal" ] || die "no frontend; set XDP_BUILD"

# shellcheck disable=SC1090
[ -f "$XDP_ENV" ] && . "$XDP_ENV"

DEVDIR="$LOGDIR/portals"
(umask 077 && mkdir -p "$DEVDIR")
xdp_write_portal_dir "$DEVDIR" "$REPO" private

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
export PKCS11_PORTAL_CERTIFICATE_KEY_ALGORITHMS=RSA
export PKCS11_PORTAL_CERTIFICATE_REASON="tools/nss-smoke.sh"
export G_MESSAGES_DEBUG=pkcs11-portal-certificate

SOFTHSM_MODULE="$(cat "$SOFTHSM_DIR/module-path")"

# OpenSSL accepts the self-signed fixture leaf as a peer trust anchor.
cat >"$LOGDIR/tls-server.py" <<'PYTHON_EOF'
import socket, ssl, sys

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
# tstclnt -Q exits on handshake completion; later I/O must not decide success.
print("PASS", subject.get("commonName", "?"), flush=True)
try:
    connection.recv(64)
    connection.sendall(b"PASS\n")
    connection.unwrap()
except Exception:
    pass
connection.close()
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

	XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL="$(xdp_experimental_portals Certificate1)" \
	"$XDP_BUILD/desktop-portal/xdg-desktop-portal" -v >"$LOGDIR/frontend.log" 2>&1 &
	FE=$!
	xdp_wait_for_name org.freedesktop.portal.Desktop "$FE" || {
		echo "nss-smoke: the frontend never took org.freedesktop.portal.Desktop"
		tail -20 "$LOGDIR/frontend.log"
		return 40
	}

	"$BACKEND" --verbose --module "$SOFTHSM_MODULE" --allow-software-tokens \
		--pin-prompt gtk >"$LOGDIR/backend.log" 2>&1 &
	BE=$!
	xdp_wait_for_name org.freedesktop.impl.portal.desktop.certificate "$BE" || {
		echo "nss-smoke: the backend never took its bus name"
		tail -20 "$LOGDIR/backend.log"
		return 40
	}

	rm -f "$LOGDIR/driver-stop"
	"$LOGDIR/driver.sh" >"$LOGDIR/driver.log" 2>&1 &
	DRIVER=$!

	grants_created() {
		grep -c 'grant-created' "$LOGDIR/backend.log" 2>/dev/null || true
	}

	# Use an empty fixture database with no password prompt.
	DB="$LOGDIR/nssdb"
	(umask 077 && mkdir -p "$DB")

	# Redirect NSS stdin to /dev/null because confirmation and password reads can otherwise block.
	"$CERTUTIL" -N -d "sql:$DB" --empty-password </dev/null >"$LOGDIR/certutil-N.log" 2>&1 || {
		echo "nss-smoke: could not create the NSS database"
		cat "$LOGDIR/certutil-N.log"
		return 40
	}

	"$MODUTIL" -dbdir "sql:$DB" -add portal -libfile "$MODULE_SO" -force \
		</dev/null >"$LOGDIR/modutil-add.log" 2>&1 || {
		echo "nss-smoke: modutil could not add the module"
		cat "$LOGDIR/modutil-add.log"
		return 40
	}

	if phase_wanted 0; then
		local before after
		echo
		echo "=== 0  token listing does not acquire credentials ==="
		before="$(grants_created)"

		timeout 180 "$MODUTIL" -dbdir "sql:$DB" -list portal \
			</dev/null >"$LOGDIR/modutil-list.log" 2>&1
		timeout 180 "$CERTUTIL" -L -d "sql:$DB" \
			</dev/null >"$LOGDIR/certutil-L-all.log" 2>&1

		after="$(grants_created)"
		grep -E 'Name:|Library file:|Slot:|Token Name:|Status:' "$LOGDIR/modutil-list.log"
		echo "grants before=$before after=$after"

		if ! grep -q "$TOKEN_LABEL" "$LOGDIR/modutil-list.log"; then
			echo "nss-smoke: NSS does not see the token"
			cat "$LOGDIR/modutil-list.log"
			rc=1
		elif [ "$before" != "$after" ]; then
			echo "nss-smoke: listing the database raised a chooser"
			grep -E 'grant-created' "$LOGDIR/backend.log" | tail -5
			rc=1
		else
			echo "nss-smoke: the token is there and neither listing acquired a credential"
		fi
	fi

	if phase_wanted 1 && [ "$rc" = 0 ]; then
		local before after
		echo
		echo "=== 1  certutil -K lists the private key without a password callback ==="
		before="$(grants_created)"

		# Private-key searches identify the credential without the class-only enumeration opt-in.
		unset PKCS11_PORTAL_CERTIFICATE_ENUMERATE
		timeout 180 "$CERTUTIL" -K -d "sql:$DB" -h "$TOKEN_LABEL" \
			</dev/null >"$LOGDIR/certutil-K.log" 2>&1
		after="$(grants_created)"

		grep -E '^<' "$LOGDIR/certutil-K.log"
		echo "grants before=$before after=$after"

		if ! grep -qE "^< *0>.*$CERT_LABEL" "$LOGDIR/certutil-K.log"; then
			echo "nss-smoke: NSS found no private key on the token"
			cat "$LOGDIR/certutil-K.log"
			rc=1
		elif grep -qiE 'Error opening input terminal|Enter Password|password.*incorrect' \
			"$LOGDIR/certutil-K.log"; then
			echo "nss-smoke: NSS ran the password callback; the token is claiming a login"
			grep -iE 'terminal|password' "$LOGDIR/certutil-K.log"
			rc=1
		elif [ "$after" != "$((before + 1))" ]; then
			echo "nss-smoke: expected exactly one chooser for one private-key search"
			rc=1
		else
			echo "nss-smoke: Private-key listing acquired one credential without login"
		fi
	fi

	if phase_wanted 2 && [ "$rc" = 0 ]; then
		local before middle after
		echo
		echo "=== 2  certutil -L: the certificate list needs the enumeration opt-in ==="
		before="$(grants_created)"

		unset PKCS11_PORTAL_CERTIFICATE_ENUMERATE
		timeout 180 "$CERTUTIL" -L -d "sql:$DB" -h "$TOKEN_LABEL" \
			</dev/null >"$LOGDIR/certutil-L-quiet.log" 2>&1
		middle="$(grants_created)"

		PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1 timeout 180 \
			"$CERTUTIL" -L -d "sql:$DB" -h "$TOKEN_LABEL" \
			</dev/null >"$LOGDIR/certutil-L.log" 2>&1
		after="$(grants_created)"

		echo "grants before=$before without=$middle with=$after"
		grep -E "$TOKEN_LABEL:" "$LOGDIR/certutil-L.log"

		if [ "$before" != "$middle" ]; then
			echo "nss-smoke: the certificate list acquired without the opt-in"
			rc=1
		elif grep -qE "$TOKEN_LABEL:" "$LOGDIR/certutil-L-quiet.log"; then
			echo "nss-smoke: certificates came out of an unacquired token"
			cat "$LOGDIR/certutil-L-quiet.log"
			rc=1
		elif ! grep -qE "^$TOKEN_LABEL:$CERT_LABEL .*u,u,u" "$LOGDIR/certutil-L.log"; then
			echo "nss-smoke: with the opt-in, NSS still did not list the certificate as a user cert"
			cat "$LOGDIR/certutil-L.log"
			rc=1
		else
			echo "nss-smoke: no chooser without the opt-in; with it, one user certificate"
		fi
	fi

	if phase_wanted 3 && [ "$rc" = 0 ]; then
		echo
		echo "=== 3  tstclnt: a real TLS client-auth handshake, NSS end to end ==="

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
			echo "nss-smoke: the TLS server did not start"
			cat "$LOGDIR/server.log"
			rc=1
		# NSS uses token:nickname; -o skips fixture server validation and -Q stops after the handshake.
		elif timeout 180 "$TSTCLNT" -h 127.0.0.1 -p "$PORT" \
			-d "sql:$DB" -n "$TOKEN_LABEL:$CERT_LABEL" -o -Q \
			</dev/null >"$LOGDIR/tstclnt.log" 2>&1; then
			grep -E "client certificate|protocol|PASS" "$LOGDIR/server.log"
			grep -q "^PASS" "$LOGDIR/server.log" || {
				echo "nss-smoke: the server did not report a client certificate"
				rc=1
			}
		else
			echo "nss-smoke: the mutual-TLS handshake did not complete"
			cat "$LOGDIR/tstclnt.log"
			cat "$LOGDIR/server.log"
			rc=1
		fi

		kill "$SERVER" 2>/dev/null
	fi

	touch "$LOGDIR/driver-stop"
	kill "$DRIVER" "$FE" "$BE" "$PERM" 2>/dev/null

	return "$rc"
}

export PIN LOGDIR REPO XDP_BUILD BACKEND MODULE_SO XDOTOOL SOFTHSM_MODULE SOFTHSM_DIR \
	PHASES TOKEN_LABEL CERT_LABEL CERTUTIL MODUTIL TSTCLNT
dbus-run-session -- bash -c \
	"$(declare -f xdp_experimental_portals); $(declare -f xdp_wait_for_name); $(declare -f phase_wanted); $(declare -f inner); inner"
rc=$?

echo
if [ "$rc" = 0 ]; then
	echo "nss-smoke: PASS; logs in $LOGDIR"
else
	echo "nss-smoke: FAIL ($rc); logs in $LOGDIR"
fi
exit "$rc"
