#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
# XDG_DESKTOP_PORTAL_DIR replaces all portal and configuration search paths; preserve the desktop's full set. See docs/TESTING.md.

set -u

here() { cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd; }
REPO="$(here)"

XDP_BUILD="${XDP_BUILD:-$REPO/../xdg-desktop-portal/build}"
BACKEND="${BACKEND:-$REPO/build/src/xdg-desktop-portal-certificate}"
XDP_ENV="${XDP_ENV:-$REPO/.xdp-env}"

FRONTEND_BIN="$XDP_BUILD/desktop-portal/xdg-desktop-portal"
PERMSTORE_BIN="$XDP_BUILD/document-portal/xdg-permission-store"

MODE=private
KEEP=0
PIN_PROMPT=
RUN_E2E=1
SOFTHSM=0
E2E_ARGS=()

die() {
	echo "${0##*/}: $*" >&2
	exit 40
}

# shellcheck source=tools/lib.sh
. "$REPO/tools/lib.sh"

# Fixture helpers validate ownership and markers before these directories are used or removed.
if [ -n "${DEVDIR:-}" ]; then
	fixture_make "$DEVDIR" dev-stack
else
	DEVDIR="$(fixture_mktemp xdp-certificate-dev dev-stack)"
fi

usage() {
	cat <<EOF
Usage: ${0##*/} [options] [-- client-options]

Run the development frontend, backend and certificate-e2e.py on a private bus.

Options:
  --live                  use the session bus and replace its running portal
  --keep                  keep the stack running after the client exits
  --no-e2e                skip the client
  --softhsm               use the tools/softhsm-fixture.sh token
  --pin-prompt KIND       select auto, gtk or system (also --pin-prompt=KIND)
  -h, --help              show this help

Private runs default to gtk; system requires --live.
The session portal returns through D-Bus activation after a live run exits.
Client options after -- are passed to certificate-e2e.py.

Environment:
  XDP_BUILD   frontend build directory (default: ../xdg-desktop-portal/build)
  BACKEND     backend binary (default: build/src/xdg-desktop-portal-certificate)
  XDP_ENV     environment file to source (default: .xdp-env if present)

See docs/TESTING.md for setup and hardware checks.
EOF
	exit 0
}

parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
		--keep) KEEP=1 ;;
		--live) MODE=live ;;
		--no-e2e) RUN_E2E=0 ;;
		--softhsm) SOFTHSM=1 ;;
		--pin-prompt=*) PIN_PROMPT="${1#--pin-prompt=}" ;;
		--pin-prompt)
			shift
			PIN_PROMPT="${1:-}"
			;;
		-h | --help) usage ;;
		--)
			shift
			E2E_ARGS=("$@")
			return
			;;
		*) die "unknown option '$1'; try --help" ;;
		esac
		shift
	done
}

preflight() {
	# shellcheck disable=SC1090
	[ -n "$XDP_ENV" ] && [ -f "$XDP_ENV" ] && . "$XDP_ENV"

	command -v dbus-run-session >/dev/null || die "dbus-run-session not found (dbus-daemon package)"
	command -v python3 >/dev/null || die "python3 not found"
	python3 -c 'import gi' 2>/dev/null || die "python3-gobject not found (the e2e client needs it)"

	[ -x "$FRONTEND_BIN" ] || die "no frontend at $FRONTEND_BIN; set XDP_BUILD"
	[ -x "$BACKEND" ] || die "no backend at $BACKEND; run 'meson setup build && ninja -C build' or set BACKEND"

	if ldd "$FRONTEND_BIN" 2>/dev/null | grep -q 'not found'; then
		echo "${0##*/}: the frontend cannot resolve its libraries:" >&2
		ldd "$FRONTEND_BIN" | grep 'not found' >&2
		echo >&2
		echo "set XDP_ENV to a file exporting LD_LIBRARY_PATH for libdex, or put one at $REPO/.xdp-env (docs/TESTING.md)" >&2
		exit 40
	fi
}

write_devdir() {
	xdp_write_portal_dir "$DEVDIR" "$REPO" "$MODE"

	echo "${0##*/}: dev portal dir $DEVDIR"
	echo "--- certificate.portal"
	sed 's/^/    /' "$DEVDIR/certificate.portal"
	echo "--- portals.conf"
	sed 's/^/    /' "$DEVDIR/portals.conf"
	echo "--- other portals (symlinked from this machine)"
	# shellcheck disable=SC2012
	ls "$DEVDIR" | grep '\.portal$' | grep -v '^certificate.portal$' | sed 's/^/    /'
	echo
}

softhsm_env() {
	[ "$SOFTHSM" = 1 ] || return 0

	: "${SOFTHSM_DIR:=${TMPDIR:-/tmp}/xdp-certificate-softhsm}"
	# Validate the fixture before loading its module path into the backend.
	fixture_check "$SOFTHSM_DIR" softhsm
	[ -f "$SOFTHSM_DIR/softhsm2.conf" ] ||
		die "no SoftHSM fixture at $SOFTHSM_DIR; run tools/softhsm-fixture.sh first"

	export SOFTHSM2_CONF="$SOFTHSM_DIR/softhsm2.conf"
	BACKEND_ARGS+=(--module "$(cat "$SOFTHSM_DIR/module-path")" --allow-software-tokens)
	echo "${0##*/}: softhsm fixture $SOFTHSM_DIR"
}

start_stack() {
	export XDG_DESKTOP_PORTAL_DIR="$DEVDIR"

	if [ "$MODE" = private ]; then
		# Preserve the session desktop so the copied configuration selects its normal backends.
		export XDG_CURRENT_DESKTOP="${XDG_CURRENT_DESKTOP:-dev}"
		"$PERMSTORE_BIN" &
		PERM_PID=$!
		sleep 1
	else
		PERM_PID=""
	fi

	# Start the frontend first because GTK settings lookup can activate the installed system portal.
	FRONTEND_LOG="$DEVDIR/frontend.log"
	if [ "$MODE" = live ]; then
		XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL="$(xdp_experimental_portals Certificate1)" \
		"$FRONTEND_BIN" -r -v > >(tee "$FRONTEND_LOG") 2>&1 &
	else
		XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL="$(xdp_experimental_portals Certificate1)" \
		"$FRONTEND_BIN" -v > >(tee "$FRONTEND_LOG") 2>&1 &
	fi
	FRONTEND_PID=$!

	xdp_wait_for_name org.freedesktop.portal.Desktop "$FRONTEND_PID" ||
		die "the frontend never took org.freedesktop.portal.Desktop"

	"$BACKEND" "${BACKEND_ARGS[@]}" &
	BACKEND_PID=$!

	xdp_wait_for_name org.freedesktop.impl.portal.desktop.certificate "$BACKEND_PID" ||
		die "the backend never took org.freedesktop.impl.portal.desktop.certificate"
}

check_frontend_log() {
	local configured="no" provided="no" i

	for i in $(seq 1 20); do
		grep -q "in configuration for org.freedesktop.impl.portal.experimental.Certificate1" \
			"$FRONTEND_LOG" 2>/dev/null && configured="yes"
		grep -q "Providing portal org.freedesktop.portal.experimental.Certificate1" \
			"$FRONTEND_LOG" 2>/dev/null && provided="yes"
		[ "$configured" = yes ] && [ "$provided" = yes ] && break
		sleep 0.25
	done

	if [ "$configured" = yes ] && [ "$provided" = yes ]; then
		echo "${0##*/}: frontend: certificate portal provided"
	else
		echo "${0##*/}: frontend: certificate portal unavailable (configured=$configured provided=$provided; see $FRONTEND_LOG)"
	fi
}

stop_stack() {
	kill "$FRONTEND_PID" "$BACKEND_PID" ${PERM_PID:+"$PERM_PID"} 2>/dev/null
	wait 2>/dev/null
}

inner() {
	BACKEND_ARGS=(--verbose)

	# Live development enables both replacement flags; installed services permit no replacement. See docs/SECURITY.md.
	if [ "$MODE" = live ]; then
		BACKEND_ARGS+=(--replace --allow-replacement)
	fi

	# Private buses share activation directories, so default to GTK instead of auto-activating a system prompter.
	[ -n "$PIN_PROMPT" ] || [ "$MODE" = live ] || PIN_PROMPT=gtk

	if [ -n "$PIN_PROMPT" ]; then
		BACKEND_ARGS+=(--pin-prompt "$PIN_PROMPT")
	fi

	softhsm_env
	start_stack

	check_frontend_log

	rc=0
	if [ "$RUN_E2E" = 1 ]; then
		python3 "$REPO/tools/certificate-e2e.py" "${E2E_ARGS[@]}"
		rc=$?
		echo
		echo "${0##*/}: certificate-e2e.py exited $rc"
	fi

	if [ "$KEEP" = 1 ]; then
		echo
		echo "${0##*/}: --keep: stack up"
		echo "  DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS"
		echo "  XDG_DESKTOP_PORTAL_DIR=$XDG_DESKTOP_PORTAL_DIR"
		echo "  Ctrl-C to tear it down"
		wait "$FRONTEND_PID"
	fi

	stop_stack
	return "$rc"
}

check_pin_prompt() {
	[ "$PIN_PROMPT" = system ] && [ "$MODE" != live ] &&
		die "--pin-prompt=system requires --live; use tools/ui-smoke.sh --pin-prompt=system for a private test prompter"
	return 0
}

main() {
	parse_args "$@"
	check_pin_prompt

	if [ "${DEV_STACK_INNER:-0}" = "1" ]; then
		trap stop_stack EXIT
		inner
		return
	fi

	preflight
	write_devdir

	if [ "$MODE" = live ]; then
		echo "${0##*/}: --live: taking org.freedesktop.portal.Desktop on the real session bus"
		echo "${0##*/}: --live: system portal returns by activation on exit (docs/TESTING.md)"
		echo
		trap 'fixture_remove "$DEVDIR" dev-stack' EXIT
		DEV_STACK_INNER=1 DEVDIR="$DEVDIR" XDP_BUILD="$XDP_BUILD" BACKEND="$BACKEND" \
			XDP_ENV="$XDP_ENV" SOFTHSM="$SOFTHSM" \
			"${BASH_SOURCE[0]}" $([ "$KEEP" = 1 ] && echo --keep) \
			$([ "$RUN_E2E" = 0 ] && echo --no-e2e) --live \
			$([ "$SOFTHSM" = 1 ] && echo --softhsm) \
			$([ -n "$PIN_PROMPT" ] && echo "--pin-prompt=$PIN_PROMPT") -- "${E2E_ARGS[@]}"
		return $?
	fi

	trap 'fixture_remove "$DEVDIR" dev-stack' EXIT
	DEV_STACK_INNER=1 DEVDIR="$DEVDIR" XDP_BUILD="$XDP_BUILD" BACKEND="$BACKEND" \
		XDP_ENV="$XDP_ENV" SOFTHSM="$SOFTHSM" \
		dbus-run-session -- "${BASH_SOURCE[0]}" \
		$([ "$KEEP" = 1 ] && echo --keep) \
		$([ "$RUN_E2E" = 0 ] && echo --no-e2e) \
		$([ "$SOFTHSM" = 1 ] && echo --softhsm) \
		$([ -n "$PIN_PROMPT" ] && echo "--pin-prompt=$PIN_PROMPT") -- "${E2E_ARGS[@]}"
}

main "$@"
