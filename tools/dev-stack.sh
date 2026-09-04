#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# dev-stack.sh -- run the experimental Certificate portal end to end: a
# development xdg-desktop-portal frontend from the branch
# experimental/certificate-webauthentication, this repository's backend, and
# then tools/certificate-e2e.py against the PUBLIC interface.
#
# Two modes.
#
#   PRIVATE BUS (the default). Everything runs inside `dbus-run-session`, so
#   nothing touches the user's real session bus. This is the mode to use for
#   everything except a run that has to show windows on the real desktop.
#
#   --live. Uses the real session bus, starts the frontend with --replace and
#     the backend with --replace --allow-replacement (a development loop only;
#     see the comment on BACKEND_ARGS and src/main.c),
#   taking org.freedesktop.portal.Desktop away from the system one for the
#   duration. THE SYSTEM PORTAL COMES BACK BY D-BUS ACTIVATION as soon as this
#   script's frontend exits and something asks for the name again; see
#   docs/TESTING.md for how to check that it did. Use this when the chooser and
#   the PIN prompt have to appear on the real display, which is what a run
#   against a real card needs.
#
#     tools/dev-stack.sh                          # private bus, no card expected
#     tools/dev-stack.sh -- --expect-no-certificate
#     tools/dev-stack.sh --keep                   # leave it up for manual gdbus
#     tools/dev-stack.sh --live -- --purpose client_auth
#     tools/dev-stack.sh --softhsm                # against a SoftHSM fixture token
#     tools/dev-stack.sh --pin-prompt=gtk         # this backend draws the PIN window
#
#   WHERE THE PIN IS TYPED. --pin-prompt is passed straight to the backend.
#   "system" needs org.gnome.keyring.SystemPrompter on the bus the backend is
#   using, and on a PRIVATE bus there is no shell to own it -- so this script
#   refuses --pin-prompt=system unless --live. The system prompter is covered
#   headlessly by `meson test pin-system` and by
#   `tools/ui-smoke.sh --pin-prompt=system`, both of which stand up gcr's own
#   server half on their private bus; docs/TESTING.md says so in one place.
#
# WHAT IT NEEDS
#
#   $XDP_BUILD   a built xdg-desktop-portal from the branch
#                experimental/certificate-webauthentication. Default:
#                ../xdg-desktop-portal/build relative to this repository. It
#                must contain desktop-portal/xdg-desktop-portal and
#                document-portal/xdg-permission-store.
#   $BACKEND     this repository's backend binary. Default:
#                ./build/src/xdg-desktop-portal-certificate
#   $XDP_ENV     a file to source first, for a frontend built against a scratch
#                prefix -- LD_LIBRARY_PATH for libdex, PKG_CONFIG_PATH,
#                GI_TYPELIB_PATH. Default: .xdp-env in this repository if it
#                exists. The frontend branch's libdex is usually not installed
#                system wide; see docs/TESTING.md.
#
# WHAT IT DOES
#
#   1. writes a throwaway $XDG_DESKTOP_PORTAL_DIR holding A SYMLINK TO EVERY
#      .portal FILE ON THE MACHINE, this repository's certificate.portal, and a
#      COPY of the machine's effective portals.conf with one line added routing
#      org.freedesktop.impl.portal.experimental.Certificate to this backend.
#
#      All of it, and not just ours, because setting XDG_DESKTOP_PORTAL_DIR
#      makes the frontend ignore every other .portal and portals.conf directory
#      on the machine (desktop-portal/xdp-portal-config.c, lines 340-344 and
#      508-516). A directory holding only certificate.portal is not "our
#      backend as well"; it is our backend and no file chooser, no screenshot
#      and NO SETTINGS -- which is why the chooser used to come up light on a
#      dark desktop, and why --live used to take every portal on the session
#      down for as long as it ran. tools/lib.sh says the same at length.
#   2. starts xdg-permission-store -- xdg-desktop-portal refuses to start
#      without it -- on the private bus. In --live mode the session's own is
#      used.
#   3. starts this repository's backend, so that its stderr is visible rather
#      than being swallowed by D-Bus activation.
#   4. starts the frontend with
#      XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate.
#   5. runs tools/certificate-e2e.py with whatever came after `--`.

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

# mktemp rather than a fixed name plus $$: a pid is guessable, and what goes in
# here decides which .portal files the frontend reads. tools/lib.sh checks that
# it is ours, that it is under $TMPDIR, and that it carries this project's
# marker, because this script `rm -rf`s it.
if [ -n "${DEVDIR:-}" ]; then
	fixture_make "$DEVDIR" dev-stack
else
	DEVDIR="$(fixture_mktemp xdp-certificate-dev dev-stack)"
fi

usage() {
	sed -n '3,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
		echo "The branch needs libdex, which Fedora does not install by default." >&2
		echo "Point XDP_ENV at a file that sets LD_LIBRARY_PATH for the scratch" >&2
		echo "prefix it was built against, or put one at $REPO/.xdp-env." >&2
		echo "docs/TESTING.md has the recipe." >&2
		exit 40
	fi
}

write_devdir() {
	xdp_write_portal_dir "$DEVDIR" "$REPO"

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
	# A software token, for proving the whole path -- chooser, PIN prompt,
	# C_Login, C_Sign, verification -- without a card. tools/softhsm-fixture.sh
	# creates it. A test that has only been run against a software token has
	# not been run; this is the rehearsal, not the performance.
	[ "$SOFTHSM" = 1 ] || return 0

	: "${SOFTHSM_DIR:=${TMPDIR:-/tmp}/xdp-certificate-softhsm}"
	# module-path out of this directory is dlopen()ed by the backend, so the
	# directory is checked before it is trusted: same rule as
	# tools/softhsm-fixture.sh, same reason.
	fixture_check "$SOFTHSM_DIR" softhsm
	[ -f "$SOFTHSM_DIR/softhsm2.conf" ] ||
		die "no SoftHSM fixture at $SOFTHSM_DIR; run tools/softhsm-fixture.sh first"

	export SOFTHSM2_CONF="$SOFTHSM_DIR/softhsm2.conf"
	# SoftHSM IS NOT A HARDWARE TOKEN and the backend's default is hardware
	# only, so the rehearsal says so out loud. --module alone would be enough --
	# naming a module is the same act -- but a flag in the command line is what
	# makes the difference between the rehearsal and a card run readable.
	BACKEND_ARGS+=(--module "$(cat "$SOFTHSM_DIR/module-path")" --allow-software-tokens)
	echo "${0##*/}: using the SoftHSM fixture in $SOFTHSM_DIR"
}

start_stack() {
	export XDG_DESKTOP_PORTAL_DIR="$DEVDIR"
	export XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate

	if [ "$MODE" = private ]; then
		# THE SESSION'S OWN DESKTOP, not "dev". The portals.conf in $DEVDIR is a
		# copy of the machine's effective one, so the backends it names are the
		# ones this desktop uses; telling the frontend it is running under a
		# desktop nobody has ever heard of would throw that away again.
		export XDG_CURRENT_DESKTOP="${XDG_CURRENT_DESKTOP:-dev}"
		"$PERMSTORE_BIN" &
		PERM_PID=$!
		sleep 1
	else
		PERM_PID=""
	fi

	# THE FRONTEND GOES UP FIRST, and this is not a preference. GTK asks the
	# settings portal for a theme as soon as the backend initialises it, which
	# on a private bus ACTIVATES org.freedesktop.portal.Desktop -- and D-Bus
	# activation finds the system portal at /usr/libexec, which then owns the
	# name this script's frontend was about to take. The development frontend
	# quits with "Terminated because dbus name was lost", and the run fails in a
	# way that reads like a portal configuration problem and is not one.
	if [ "$MODE" = live ]; then
		"$FRONTEND_BIN" -r -v &
	else
		"$FRONTEND_BIN" -v &
	fi
	FRONTEND_PID=$!

	# WAIT FOR THE NAME, DO NOT SLEEP AND HOPE. Loading the PKCS#11 modules
	# takes a couple of seconds on a machine with several configured, and the
	# backend requests its name only after that -- so a fixed sleep raced it and
	# the frontend's first call came back "was not provided by any .service
	# files", there being no activation file on a private bus.
	xdp_wait_for_name org.freedesktop.portal.Desktop "$FRONTEND_PID" ||
		die "the frontend never took org.freedesktop.portal.Desktop"

	"$BACKEND" "${BACKEND_ARGS[@]}" &
	BACKEND_PID=$!

	xdp_wait_for_name org.freedesktop.impl.portal.desktop.certificate "$BACKEND_PID" ||
		die "the backend never took org.freedesktop.impl.portal.desktop.certificate"
}

stop_stack() {
	kill "$FRONTEND_PID" "$BACKEND_PID" ${PERM_PID:+"$PERM_PID"} 2>/dev/null
	wait 2>/dev/null
}

inner() {
	BACKEND_ARGS=(--verbose)

	# A DEVELOPMENT LOOP, AND ONLY A DEVELOPMENT LOOP. The backend refuses to be
	# replaced unless it was started with --allow-replacement, because D-Bus
	# cannot tell "the package manager" from "any process running as this user"
	# and the thing that would be taken over is the window that asks for a PIN.
	# On the real bus that means re-running this script would otherwise fail to
	# get the name off the instance the last run left behind, so --live opts in
	# to both halves: take the name, and be takeable in turn. The installed
	# .service file passes neither, and docs/SECURITY.md says why.
	if [ "$MODE" = live ]; then
		BACKEND_ARGS+=(--replace --allow-replacement)
	fi

	if [ -n "$PIN_PROMPT" ]; then
		BACKEND_ARGS+=(--pin-prompt "$PIN_PROMPT")
	fi

	softhsm_env
	start_stack

	echo
	echo "=== expected in the frontend log above:"
	echo "===   Found 'certificate' in configuration for org.freedesktop.impl.portal.experimental.Certificate"
	echo "===   Providing portal org.freedesktop.portal.experimental.Certificate"
	echo

	rc=0
	if [ "$RUN_E2E" = 1 ]; then
		python3 "$REPO/tools/certificate-e2e.py" "${E2E_ARGS[@]}"
		rc=$?
		echo
		echo "${0##*/}: certificate-e2e.py exited $rc"
	fi

	if [ "$KEEP" = 1 ]; then
		echo
		echo "${0##*/}: --keep: the stack is up."
		echo "  DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS"
		echo "  XDG_DESKTOP_PORTAL_DIR=$XDG_DESKTOP_PORTAL_DIR"
		echo "  run tools/certificate-e2e.py from another shell with that address,"
		echo "  or gdbus introspect --session --dest org.freedesktop.portal.Desktop \\"
		echo "      --object-path /org/freedesktop/portal/desktop"
		echo "  Ctrl-C to tear it down."
		wait "$FRONTEND_PID"
	fi

	stop_stack
	return "$rc"
}

# Refused before anything is started or written, rather than after: a private
# bus has no shell to own org.gnome.keyring.SystemPrompter, so the backend
# would come up, answer no_display at the first Sign, and look like a bug.
check_pin_prompt() {
	[ "$PIN_PROMPT" = system ] && [ "$MODE" != live ] &&
		die "--pin-prompt=system needs a system prompter on the bus, and a private
bus has no shell to own org.gnome.keyring.SystemPrompter. Use --live, or
tools/ui-smoke.sh --pin-prompt=system, which brings its own."
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
		echo "${0##*/}: --live: taking org.freedesktop.portal.Desktop on the REAL session bus."
		echo "${0##*/}: the system portal returns by activation when this exits; see docs/TESTING.md."
		echo
		trap 'fixture_remove "$DEVDIR" dev-stack' EXIT
		DEV_STACK_INNER=1 DEVDIR="$DEVDIR" XDP_BUILD="$XDP_BUILD" BACKEND="$BACKEND" \
			XDP_ENV="$XDP_ENV" SOFTHSM="$SOFTHSM" \
			"${BASH_SOURCE[0]}" $([ "$KEEP" = 1 ] && echo --keep) \
			$([ "$RUN_E2E" = 0 ] && echo --no-e2e) --live \
			$([ "$SOFTHSM" = 1 ] && echo --softhsm) -- "${E2E_ARGS[@]}"
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
