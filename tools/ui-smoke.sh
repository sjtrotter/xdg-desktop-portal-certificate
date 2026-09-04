#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# ui-smoke.sh -- the whole thing, WINDOWS INCLUDED, with nobody at the keyboard.
#
# Runs the private-bus stack inside a headless X server and drives the chooser
# and the PIN prompt with xdotool: down-arrow, Return, type the PIN, Return.
# Then tools/certificate-e2e.py verifies the signature that comes back.
#
# THIS IS THE ONLY AUTOMATED TEST THAT OPENS THE WINDOWS. tests/ covers the
# rules and the cryptography with no display; this covers everything between a
# D-Bus call and a user's Return key, which is where the interesting mistakes
# live -- the first thing it ever found was a use-after-free in the chooser's
# row-selected handler during window teardown, which every hand-run of the real
# thing would have hit and no unit test could have.
#
# It is NOT a substitute for docs/TESTING.md. A software token in a headless X
# server is a rehearsal: it has no reader, no PIN retry counter to spend, and
# nothing to pull out mid-signature.
#
# WHAT IT NEEDS, none of which has to be installed system wide:
#
#   Xvfb        xorg-x11-server-Xvfb
#   xdotool     xdotool
#   a SoftHSM fixture from tools/softhsm-fixture.sh
#   a built frontend, as tools/dev-stack.sh describes
#
# Without root, 'dnf download' plus 'rpm2cpio | cpio -idmu' into a scratch
# directory is enough for the first two; point $XVFB and $XDOTOOL at them.
#
#     tools/ui-smoke.sh
#     tools/ui-smoke.sh --purpose signing --key-algorithm EC --der

set -u

here() { cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd; }
REPO="$(here)"

XDP_BUILD="${XDP_BUILD:-$REPO/../xdg-desktop-portal/build}"
BACKEND="${BACKEND:-$REPO/build/src/xdg-desktop-portal-certificate}"
XDP_ENV="${XDP_ENV:-$REPO/.xdp-env}"
SOFTHSM_DIR="${SOFTHSM_DIR:-${TMPDIR:-/tmp}/xdp-certificate-softhsm}"
XVFB="${XVFB:-$(command -v Xvfb || true)}"
XDOTOOL="${XDOTOOL:-$(command -v xdotool || true)}"
PIN="${PIN:-123456}"
SCREEN="${SCREEN:-:77}"
LOGDIR="${LOGDIR:-${TMPDIR:-/tmp}/xdp-certificate-ui-smoke}"

die() {
	echo "${0##*/}: $*" >&2
	exit 40
}

[ -n "$XVFB" ] || die "Xvfb not found; set \$XVFB"
[ -n "$XDOTOOL" ] || die "xdotool not found; set \$XDOTOOL"
[ -f "$SOFTHSM_DIR/module-path" ] || die "no SoftHSM fixture; run tools/softhsm-fixture.sh"
[ -x "$BACKEND" ] || die "no backend at $BACKEND"
[ -x "$XDP_BUILD/desktop-portal/xdg-desktop-portal" ] || die "no frontend; set XDP_BUILD"

# shellcheck disable=SC1090
[ -f "$XDP_ENV" ] && . "$XDP_ENV"

mkdir -p "$LOGDIR"
DEVDIR="$LOGDIR/portals"
rm -rf -- "$DEVDIR"
mkdir -p "$DEVDIR"

sed -e '/^#/d' -e '/^$/d' "$REPO/data/certificate.portal.in" >"$DEVDIR/certificate.portal"
cat >"$DEVDIR/portals.conf" <<-EOF
	[preferred]
	default=none;
	org.freedesktop.impl.portal.experimental.Certificate=certificate;
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
# X11 rather than Wayland, because a headless X server is something a machine
# with no compositor can start and xdotool can drive.
export GDK_BACKEND=x11
export GTK_A11Y=none
export SOFTHSM2_CONF="$SOFTHSM_DIR/softhsm2.conf"
export XDG_DESKTOP_PORTAL_DIR="$DEVDIR"
export XDG_CURRENT_DESKTOP=dev
export XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate

MODULE="$(cat "$SOFTHSM_DIR/module-path")"

inner() {
	"$XDP_BUILD/document-portal/xdg-permission-store" >"$LOGDIR/permission-store.log" 2>&1 &
	PERM=$!
	sleep 1
	"$BACKEND" --verbose --module "$MODULE" >"$LOGDIR/backend.log" 2>&1 &
	BE=$!
	"$XDP_BUILD/desktop-portal/xdg-desktop-portal" -v >"$LOGDIR/frontend.log" 2>&1 &
	FE=$!
	sleep 3

	python3 "$REPO/tools/certificate-e2e.py" --timeout 45000 "$@" >"$LOGDIR/e2e.log" 2>&1 &
	E2E=$!

	drive() {
		local title="$1"
		shift
		local wid=""

		for _ in $(seq 1 40); do
			wid="$("$XDOTOOL" search --name "$title" 2>/dev/null | tail -1)"
			[ -n "$wid" ] && break
			sleep 0.5
		done

		[ -n "$wid" ] || {
			echo "ui-smoke: no window titled '$title'"
			return 1
		}

		echo "ui-smoke: driving '$title'"
		# There is no window manager, so focus is set directly and the keys go
		# through XTEST to whatever has it.
		"$XDOTOOL" windowfocus "$wid" 2>/dev/null
		sleep 1

		for key in "$@"; do
			case "$key" in
			type:*) "$XDOTOOL" type --delay 60 "${key#type:}" ;;
			*) "$XDOTOOL" key "$key" ;;
			esac
			sleep 0.8
		done
	}

	drive "Use a Certificate" Down Return
	drive "Unlock Security Token" "type:$PIN" Return

	wait "$E2E"
	rc=$?

	kill "$FE" "$BE" "$PERM" 2>/dev/null
	return "$rc"
}

dbus-run-session -- bash -c "$(declare -f inner); LOGDIR='$LOGDIR' REPO='$REPO' XDP_BUILD='$XDP_BUILD' BACKEND='$BACKEND' MODULE='$MODULE' XDOTOOL='$XDOTOOL' PIN='$PIN' inner \"\$@\"" -- "$@"
rc=$?

echo
sed -n '/^GetCapabilities/,$p' "$LOGDIR/e2e.log"
echo
echo "ui-smoke: certificate-e2e.py exited $rc; logs in $LOGDIR"
exit "$rc"
