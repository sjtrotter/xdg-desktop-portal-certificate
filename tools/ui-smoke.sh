#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
# Drive the private-bus stack under Xvfb; see docs/TESTING.md for prerequisites and hardware checks.

set -u

here() { cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd; }
REPO="$(here)"

XDP_BUILD="${XDP_BUILD:-$REPO/../xdg-desktop-portal/build}"
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
xdp_smoke_select_backend "$REPO/build/src/xdg-desktop-portal-certificate"

if [ -n "${LOGDIR:-}" ]; then
	fixture_make "$LOGDIR" ui-smoke
else
	LOGDIR="$(fixture_mktemp xdp-certificate-ui-smoke ui-smoke)"
fi

[ -n "$XVFB" ] || die "Xvfb not found; set \$XVFB"
[ -n "$XDOTOOL" ] || die "xdotool not found; set \$XDOTOOL"
# Validate the fixture before the backend loads its module path.
fixture_check "$SOFTHSM_DIR" softhsm
[ -f "$SOFTHSM_DIR/module-path" ] || die "no SoftHSM fixture; run tools/softhsm-fixture.sh"
[ -x "$BACKEND" ] || die "no backend at $BACKEND"
[ -x "$XDP_BUILD/desktop-portal/xdg-desktop-portal" ] || die "no frontend; set XDP_BUILD"

# shellcheck disable=SC1090
[ -f "$XDP_ENV" ] && . "$XDP_ENV"

DEVDIR="$LOGDIR/portals"
(umask 077 && mkdir -p "$DEVDIR")
xdp_smoke_prepare "$LOGDIR" "$REPO" "$SOFTHSM_DIR"

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
# Preserve the session desktop for its copied portals.conf.
export XDG_CURRENT_DESKTOP="${XDG_CURRENT_DESKTOP:-dev}"

MODULE="$(cat "$SOFTHSM_DIR/module-path")"

DRIVE_WINDOWS=1
PIN_PROMPT=gtk
CANCEL_DIALOG=""
while [ $# -gt 0 ]; do
	case "$1" in
	--cancel-chooser | --cancel-pin)
		CANCEL_DIALOG="${1#--cancel-}"
		shift
		;;
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

if [ "$BACKEND_KIND" = kde ]; then
	if [ "$PIN_PROMPT" = system ]; then
		echo "ui-smoke: SKIP gcr system prompter: KDE uses its native PIN dialog; exercising that dialog instead"
	fi
	PIN_PROMPT=kde
elif [ "$BACKEND_KIND" = gnome ]; then
	if [ "$PIN_PROMPT" = system ]; then
		# Preparation defaults every GNOME smoke runner to the GTK dialog.
		# Only this explicit run selects Gcr on the temporary private-bus config.
		sed -i 's/^PinPrompt=dialog$/PinPrompt=system/' \
			"$LOGDIR/gnome-config/xdg-desktop-portal-gnome/certificate.conf"
	else
		PIN_PROMPT=gnome
	fi
fi
[ -z "$CANCEL_DIALOG" ] || set -- --expect-user-cancelled "$CANCEL_DIALOG" "$@"

if [ "$BACKEND_KIND" = gnome ]; then
	PROMPTER_BIN="${PROMPTER_BIN:-${BUILD:-$REPO/build}/tests/certificate-test-prompter}"
else
	PROMPTER_BIN="${PROMPTER_BIN:-$(dirname -- "$BACKEND")/../tests/certificate-test-prompter}"
fi
if [ "$PIN_PROMPT" = system ]; then
	[ -x "$PROMPTER_BIN" ] ||
		die "no test prompter at $PROMPTER_BIN.
It is built only when the build found gcr-4; check 'meson configure build | grep gcr'."
fi

inner() {
	# Sourced inside the new bus; KDE must be running before frontend discovery.
	. "$REPO/tools/lib.sh"
	trap 'kill ${PROMPTER:+"$PROMPTER"} ${BE:+"$BE"} ${FE:+"$FE"} ${PERM:+"$PERM"} ${E2E:+"$E2E"} 2>/dev/null' EXIT
	# The system prompter must own its name before the backend's first private-key operation.
	PROMPTER=""
	if [ "$PIN_PROMPT" = system ]; then
		TEST_PROMPTER_PIN="$PIN" "$PROMPTER_BIN" >"$LOGDIR/prompter.log" 2>&1 &
		PROMPTER=$!
		xdp_wait_for_name org.gnome.keyring.SystemPrompter "$PROMPTER" &&
			grep -q 'serving' "$LOGDIR/prompter.log" || {
			echo "ui-smoke: the test prompter did not start:"
			cat "$LOGDIR/prompter.log"
			return 40
		}
	fi

	if [ "$BACKEND_KIND" = kde ]; then
		xdp_smoke_start_kde_backend || return 40
	elif [ "$BACKEND_KIND" = gnome ]; then
		xdp_smoke_start_gnome_backend || return 40
	fi

	"$XDP_BUILD/document-portal/xdg-permission-store" >"$LOGDIR/permission-store.log" 2>&1 &
	PERM=$!
	sleep 1

	# Start the frontend before GTK settings lookup can activate the installed portal.
	XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL="$(xdp_experimental_portals Certificate1)" \
	"$XDP_BUILD/desktop-portal/xdg-desktop-portal" -v >"$LOGDIR/frontend.log" 2>&1 &
	FE=$!
	xdp_wait_for_name org.freedesktop.portal.Desktop "$FE" || {
		echo "ui-smoke: the frontend never took org.freedesktop.portal.Desktop"
		tail -20 "$LOGDIR/frontend.log"
		return 40
	}

	if [ "$BACKEND_KIND" = gtk ]; then
		"$BACKEND" --verbose --module "$MODULE" --allow-software-tokens \
			--pin-prompt "$PIN_PROMPT" >"$LOGDIR/backend.log" 2>&1 &
		BE=$!
		xdp_wait_for_name org.freedesktop.impl.portal.desktop.certificate "$BE" || {
			echo "ui-smoke: the backend never took its bus name"
			tail -20 "$LOGDIR/backend.log"
			return 40
		}
	fi

	python3 "$REPO/tools/certificate-e2e.py" --timeout 45000 "$@" >"$LOGDIR/e2e.log" 2>&1 &
	E2E=$!

	drive() {
		local title="$1"
		shift
		local wid=""
		local visibility=()
		[ "$BACKEND_KIND" != gtk ] && visibility=(--onlyvisible)

		for _ in $(seq 1 40); do
			wid="$("$XDOTOOL" search "${visibility[@]}" --name "$title" 2>/dev/null | tail -1)"
			[ -n "$wid" ] && break
			sleep 0.5
		done

		[ -n "$wid" ] || {
			echo "ui-smoke: no window titled '$title'"
			return 1
		}

		echo "ui-smoke: driving '$title'"
		# Without a window manager, set focus directly before XTEST input.
		"$XDOTOOL" windowfocus "$wid" 2>/dev/null
		sleep 1

		for key in "$@"; do
			case "$key" in
			# Send PIN input through stdin to keep it out of /proc/*/cmdline.
			type:) printf '%s' "$PIN" | "$XDOTOOL" type --delay 60 --file - ;;
			type:*) "$XDOTOOL" type --delay 60 "${key#type:}" ;;
			*) "$XDOTOOL" key "$key" ;;
			esac
			sleep 0.8
		done
	}

	if [ "$DRIVE_WINDOWS" = 1 ]; then
		if [ "$CANCEL_DIALOG" = chooser ]; then
			drive "$CHOOSER_TITLE" Escape
		else
			drive "$CHOOSER_TITLE" Down Return
			if [ "$CANCEL_DIALOG" = pin ]; then
				drive "$PIN_TITLE" Escape
			elif [ "$PIN_PROMPT" != system ]; then
				drive "$PIN_TITLE" "type:" Return
			fi
		fi

		# Regrant uses a second session and requires another chooser and PIN interaction.
		for arg in "$@"; do
			if [ "$arg" = --regrant ]; then
				drive "$CHOOSER_TITLE" Down Return
				[ "$PIN_PROMPT" != system ] && drive "$PIN_TITLE" "type:" Return
				break
			fi
		done
	else
		echo "ui-smoke: --no-drive: windows up, not driven"
	fi

	wait "$E2E"
	rc=$?

	kill "$FE" "$BE" "$PERM" ${PROMPTER:+"$PROMPTER"} 2>/dev/null
	return "$rc"
}

# Pass the PIN through the environment to keep it out of the public command line.
export PIN LOGDIR REPO XDP_BUILD BACKEND MODULE XDOTOOL DRIVE_WINDOWS PIN_PROMPT PROMPTER_BIN CANCEL_DIALOG
xdp_smoke_run_session bash -c "$(declare -f xdp_experimental_portals); $(declare -f xdp_wait_for_name); $(declare -f inner); inner \"\$@\"" -- "$@"
rc=$?

echo
sed -n '/^GetCapabilities/,$p' "$LOGDIR/e2e.log"
echo
echo "ui-smoke: certificate-e2e.py exited $rc; logs in $LOGDIR"
exit "$rc"
