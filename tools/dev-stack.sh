#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# dev-stack.sh -- run the experimental Certificate portal end to end on a
# PRIVATE session bus: a development xdg-desktop-portal frontend, this
# repository's backend, and then tools/trigger-certificate.sh against them.
#
# Nothing here touches the user's real session bus. Everything runs inside
# `dbus-run-session`, which is why the script re-executes itself: the outer
# invocation starts a private bus, the inner one is the payload.
#
#     tools/dev-stack.sh                  # build dir found via $XDP_BUILD
#     XDP_BUILD=/path/to/xdp/build tools/dev-stack.sh
#
# WHAT IT NEEDS
#
#   $XDP_BUILD          a built xdg-desktop-portal from the branch
#                       experimental/certificate-webauthentication.
#                       Default: ../xdg-desktop-portal/build, relative to this
#                       repository. It must contain
#                       desktop-portal/xdg-desktop-portal and
#                       document-portal/xdg-permission-store.
#   $BACKEND            this repository's backend binary.
#                       Default: ./build/xdg-desktop-portal-certificate
#   $XDP_ENV            optional file to source first, for a scratch-prefix
#                       build (LD_LIBRARY_PATH, PKG_CONFIG_PATH, PATH...).
#
# WHAT IT DOES
#
#   1. writes a throwaway $XDG_DESKTOP_PORTAL_DIR containing this repository's
#      certificate.portal (rewritten to point at whatever backend binary is
#      being tested) and a portals.conf selecting it. Setting
#      XDG_DESKTOP_PORTAL_DIR makes the frontend ignore every other .portal and
#      portals.conf directory on the machine
#      (desktop-portal/xdp-portal-config.c, lines 340-344 and 508-516), so
#      nothing installed system-wide can interfere.
#   2. starts xdg-permission-store -- xdg-desktop-portal refuses to start
#      without it.
#   3. starts this repository's backend on the private bus.
#   4. starts the frontend with
#      XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate.
#   5. runs tools/trigger-certificate.sh.
#
# THE BACKEND IS A STUB THAT EXITS 70, so step 5 will not get a credential. What
# it does show is the wiring: that the frontend finds the .portal file, matches
# the impl interface, exports the public one, and activates the backend.

set -u

here() { cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd; }
REPO="$(here)"

XDP_BUILD="${XDP_BUILD:-$REPO/../xdg-desktop-portal/build}"
BACKEND="${BACKEND:-$REPO/build/xdg-desktop-portal-certificate}"
XDP_ENV="${XDP_ENV:-}"
DEVDIR="${DEVDIR:-${TMPDIR:-/tmp}/xdp-certificate-dev.$$}"

FRONTEND_BIN="$XDP_BUILD/desktop-portal/xdg-desktop-portal"
PERMSTORE_BIN="$XDP_BUILD/document-portal/xdg-permission-store"

die() {
	echo "${0##*/}: $*" >&2
	exit 40
}

preflight() {
	[ -n "$XDP_ENV" ] && [ -f "$XDP_ENV" ] && . "$XDP_ENV"
	command -v dbus-run-session >/dev/null || die "dbus-run-session not found (dbus-daemon package)"
	command -v gdbus >/dev/null || die "gdbus not found (glib2 tools)"
	[ -x "$FRONTEND_BIN" ] || die "no frontend at $FRONTEND_BIN; set XDP_BUILD"
	[ -x "$PERMSTORE_BIN" ] || die "no permission store at $PERMSTORE_BIN; set XDP_BUILD"
	[ -x "$BACKEND" ] || die "no backend at $BACKEND; run 'meson setup build && ninja -C build' or set BACKEND"
}

write_devdir() {
	mkdir -p "$DEVDIR"
	# The installed .portal file names the installed binary. Here we want the
	# one just built, so the D-Bus service file is written against $BACKEND.
	sed -e '/^#/d' -e '/^$/d' "$REPO/data/certificate.portal.in" >"$DEVDIR/certificate.portal"
	cat >"$DEVDIR/portals.conf" <<-EOF
		[preferred]
		default=certificate;
	EOF
	mkdir -p "$DEVDIR/services"
	cat >"$DEVDIR/services/org.freedesktop.impl.portal.desktop.certificate.service" <<-EOF
		[D-BUS Service]
		Name=org.freedesktop.impl.portal.desktop.certificate
		Exec=$BACKEND
	EOF
	echo "${0##*/}: dev portal dir $DEVDIR"
	echo "--- certificate.portal"
	cat "$DEVDIR/certificate.portal"
	echo "--- portals.conf"
	cat "$DEVDIR/portals.conf"
}

inner() {
	# Everything from here runs on the private bus dbus-run-session made.
	export XDG_DESKTOP_PORTAL_DIR="$DEVDIR"
	export XDG_CURRENT_DESKTOP=dev
	export XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate

	"$PERMSTORE_BIN" &
	PERM_PID=$!
	sleep 1

	# Started explicitly rather than by activation, so its stderr is visible.
	"$BACKEND" &
	BACKEND_PID=$!

	"$FRONTEND_BIN" -v &
	FRONTEND_PID=$!
	sleep 2

	trap 'kill $FRONTEND_PID $BACKEND_PID $PERM_PID 2>/dev/null; wait 2>/dev/null' EXIT

	echo
	echo "=== expected in the frontend log above:"
	echo "===   Found 'certificate' in configuration for org.freedesktop.impl.portal.experimental.Certificate"
	echo "===   Providing portal org.freedesktop.portal.experimental.Certificate"
	echo

	"$REPO/tools/trigger-certificate.sh" all
	rc=$?

	echo
	echo "${0##*/}: trigger exited $rc (the backend is a stub; a non-zero result here is expected)"
	return 0
}

main() {
	if [ "${DEV_STACK_INNER:-0}" = "1" ]; then
		inner
		return
	fi
	preflight
	write_devdir
	trap 'rm -rf -- "$DEVDIR"' EXIT
	DEV_STACK_INNER=1 DEVDIR="$DEVDIR" XDP_BUILD="$XDP_BUILD" BACKEND="$BACKEND" \
		dbus-run-session -- "${BASH_SOURCE[0]}"
}

main "$@"
