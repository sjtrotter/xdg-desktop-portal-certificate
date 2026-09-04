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
#
# --no-drive leaves the windows alone, so that the client can cancel instead:
#
#     tools/ui-smoke.sh --no-drive -- --cancel-after 3000 --expect-cancelled
#
# A second AcquireCredential on the same session -- two choosers and, because
# the grant changed, TWO PIN prompts. It fails if the second signature does not
# verify against the second certificate:
#
#     tools/ui-smoke.sh -- --key-algorithm RSA --regrant EC
#
# THE OTHER PIN PROMPT. --pin-prompt=system runs the same stack against the
# system-prompter implementation instead of the in-process window: this script
# starts build/tests/certificate-test-prompter on the private bus, which owns
# org.gnome.keyring.SystemPrompter there and answers with $PIN. Nothing is typed
# and xdotool is not used for the PIN, so the run also proves that path needs no
# display of this backend's own.
#
#     tools/ui-smoke.sh --pin-prompt=system

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

die() {
	echo "${0##*/}: $*" >&2
	exit 40
}

# shellcheck source=tools/lib.sh
. "$REPO/tools/lib.sh"

# A FRESH DIRECTORY WITH AN UNGUESSABLE NAME, not a fixed path under /tmp:
# nothing else has to find these logs, so nothing else has to be able to
# predict where they are. tools/lib.sh checks that anything given in $LOGDIR is
# ours, is under $TMPDIR and carries this project's marker.
if [ -n "${LOGDIR:-}" ]; then
	fixture_make "$LOGDIR" ui-smoke
else
	LOGDIR="$(fixture_mktemp xdp-certificate-ui-smoke ui-smoke)"
fi

[ -n "$XVFB" ] || die "Xvfb not found; set \$XVFB"
[ -n "$XDOTOOL" ] || die "xdotool not found; set \$XDOTOOL"
# The module path in here is dlopen()ed by the backend, so the directory it
# comes out of is checked the same way tools/softhsm-fixture.sh checks it.
fixture_check "$SOFTHSM_DIR" softhsm
[ -f "$SOFTHSM_DIR/module-path" ] || die "no SoftHSM fixture; run tools/softhsm-fixture.sh"
[ -x "$BACKEND" ] || die "no backend at $BACKEND"
[ -x "$XDP_BUILD/desktop-portal/xdg-desktop-portal" ] || die "no frontend; set XDP_BUILD"

# shellcheck disable=SC1090
[ -f "$XDP_ENV" ] && . "$XDP_ENV"

# EVERY .portal ON THE MACHINE, plus ours, plus a copy of the machine's
# portals.conf with one line added. XDG_DESKTOP_PORTAL_DIR makes the frontend
# ignore every other portal directory AND every other portals.conf, so a
# directory holding only certificate.portal leaves the stack with no settings
# portal -- which is why the windows used to come up light on a dark desktop.
# tools/lib.sh says it at length.
DEVDIR="$LOGDIR/portals"
(umask 077 && mkdir -p "$DEVDIR")
xdp_write_portal_dir "$DEVDIR" "$REPO"

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
# The session's own desktop, not "dev": the portals.conf in $DEVDIR is a copy of
# the machine's, so the backends it names are the ones this desktop uses.
export XDG_CURRENT_DESKTOP="${XDG_CURRENT_DESKTOP:-dev}"
export XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate

MODULE="$(cat "$SOFTHSM_DIR/module-path")"

# --no-drive: put the windows up and touch nothing, for the paths where the
# point is that something else ends the interaction -- Request.Close() from the
# frontend, or a timeout.
DRIVE_WINDOWS=1
PIN_PROMPT=gtk
while [ $# -gt 0 ]; do
	case "$1" in
	--no-drive)
		DRIVE_WINDOWS=0
		shift
		;;
	--pin-prompt=*)
		PIN_PROMPT="${1#--pin-prompt=}"
		shift
		;;
	*) break ;;
	esac
done
[ "${1:-}" = "--" ] && shift

case "$PIN_PROMPT" in
gtk | system) ;;
*) die "--pin-prompt takes gtk or system here; 'auto' would depend on what is on the bus" ;;
esac

PROMPTER_BIN="${PROMPTER_BIN:-$(dirname -- "$BACKEND")/../tests/certificate-test-prompter}"
if [ "$PIN_PROMPT" = system ]; then
	[ -x "$PROMPTER_BIN" ] ||
		die "no test prompter at $PROMPTER_BIN.
It is built only when the build found gcr-4; check 'meson configure build | grep gcr'."
fi

inner() {
	"$XDP_BUILD/document-portal/xdg-permission-store" >"$LOGDIR/permission-store.log" 2>&1 &
	PERM=$!
	sleep 1

	# THE FRONTEND GOES UP FIRST, and this is not a preference. GTK asks the
	# settings portal for a colour scheme as soon as the backend initialises it,
	# which on a private bus ACTIVATES org.freedesktop.portal.Desktop -- and
	# activation finds the SYSTEM portal at /usr/libexec, which then owns the
	# name this script's frontend was about to take. tools/dev-stack.sh has done
	# this since the day it hit that; this script had not, and it only started
	# failing once the portal directory grew a settings backend for GTK to
	# reach.
	"$XDP_BUILD/desktop-portal/xdg-desktop-portal" -v >"$LOGDIR/frontend.log" 2>&1 &
	FE=$!
	xdp_wait_for_name org.freedesktop.portal.Desktop "$FE" || {
		echo "ui-smoke: the frontend never took org.freedesktop.portal.Desktop"
		tail -20 "$LOGDIR/frontend.log"
		return 40
	}

	# THE PROMPTER GOES UP BEFORE THE BACKEND, because the backend resolves
	# --pin-prompt=auto by asking the bus once. Here the choice is explicit, but
	# the prompter still has to be there before the first Sign.
	PROMPTER=""
	if [ "$PIN_PROMPT" = system ]; then
		TEST_PROMPTER_PIN="$PIN" "$PROMPTER_BIN" >"$LOGDIR/prompter.log" 2>&1 &
		PROMPTER=$!
		sleep 1
		grep -q 'serving' "$LOGDIR/prompter.log" || {
			echo "ui-smoke: the test prompter did not start:"
			cat "$LOGDIR/prompter.log"
			return 40
		}
	fi

	"$BACKEND" --verbose --module "$MODULE" --allow-software-tokens \
		--pin-prompt "$PIN_PROMPT" >"$LOGDIR/backend.log" 2>&1 &
	BE=$!
	xdp_wait_for_name org.freedesktop.impl.portal.desktop.certificate "$BE" || {
		echo "ui-smoke: the backend never took its bus name"
		tail -20 "$LOGDIR/backend.log"
		return 40
	}

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
			# THE PIN IS NOT AN ARGUMENT. xdotool --file - reads what to type
			# from stdin, so it never appears in /proc/*/cmdline. "type:" with
			# no value means "the PIN", which is the only secret this script
			# has; anything after "type:" is literal and public.
			type:) printf '%s' "$PIN" | "$XDOTOOL" type --delay 60 --file - ;;
			type:*) "$XDOTOOL" type --delay 60 "${key#type:}" ;;
			*) "$XDOTOOL" key "$key" ;;
			esac
			sleep 0.8
		done
	}

	if [ "$DRIVE_WINDOWS" = 1 ]; then
		drive "Use a Certificate" Down Return
		# WITH THE SYSTEM PROMPTER THERE IS NO WINDOW TO DRIVE. The PIN field is
		# the prompter's, and the prompter answers from $TEST_PROMPTER_PIN -- so
		# a run that gets a signature back has proved the whole path without
		# anything typing into anything.
		[ "$PIN_PROMPT" = gtk ] && drive "Unlock Security Token" "type:" Return

		# --regrant asks for a SECOND credential on the same session, so there
		# is a second chooser and -- this is the point -- a SECOND PIN prompt.
		# A backend that reused the first grant's token session would show no
		# second prompt at all, and this would time out looking for it.
		for arg in "$@"; do
			if [ "$arg" = --regrant ]; then
				drive "Use a Certificate" Down Return
				[ "$PIN_PROMPT" = gtk ] && drive "Unlock Security Token" "type:" Return
				break
			fi
		done
	else
		echo "ui-smoke: --no-drive: the windows are up and nothing will touch them"
	fi

	wait "$E2E"
	rc=$?

	kill "$FE" "$BE" "$PERM" ${PROMPTER:+"$PROMPTER"} 2>/dev/null
	return "$rc"
}

# THE PIN GOES THROUGH THE ENVIRONMENT, NOT ARGV. /proc/*/cmdline is readable
# by every user on the machine and /proc/*/environ is not. It is the fixture PIN
# today; it is also the line anyone adapting this script for a card will copy.
export PIN LOGDIR REPO XDP_BUILD BACKEND MODULE XDOTOOL DRIVE_WINDOWS PIN_PROMPT PROMPTER_BIN
dbus-run-session -- bash -c "$(declare -f xdp_wait_for_name); $(declare -f inner); inner \"\$@\"" -- "$@"
rc=$?

echo
sed -n '/^GetCapabilities/,$p' "$LOGDIR/e2e.log"
echo
echo "ui-smoke: certificate-e2e.py exited $rc; logs in $LOGDIR"
exit "$rc"
