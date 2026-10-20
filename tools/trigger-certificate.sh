#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
# Calls targeting Certificate1 fail when it is not exported; introspect can still list other interfaces at the shared object path.

set -eu

BUS="${BUS:---session}"          # --session (default) or --system
DEST=org.freedesktop.portal.Desktop
PATH_=/org/freedesktop/portal/desktop
IFACE=org.freedesktop.portal.experimental.Certificate1

usage() {
	cat <<EOF
Usage: ${0##*/} [command]

Commands:
  version        read the interface's version property (works with no backend
                 running, as long as the interface is exported)
  introspect     list the interfaces the portal exports on the desktop path
  capabilities   GetCapabilities(a{sv}) -> a{sv}; a plain method, answers directly
  all            version + capabilities (default)

Use tools/certificate-e2e.py for session creation, acquisition and signing.
It keeps the session's D-Bus connection open through release.

Environment:
  BUS            --session (default) or --system
EOF
}

cmd_version() {
	gdbus call "$BUS" --dest "$DEST" --object-path "$PATH_" \
		--method org.freedesktop.DBus.Properties.Get \
		"$IFACE" version
}

cmd_introspect() {
	gdbus introspect "$BUS" --dest "$DEST" --object-path "$PATH_" |
		grep -E '^[[:space:]]*interface org\.freedesktop\.portal\.' ||
		echo "No portal interfaces exported"
}

cmd_capabilities() {
	gdbus call "$BUS" --dest "$DEST" --object-path "$PATH_" \
		--method "$IFACE".GetCapabilities "{}"
}

main() {
	local cmd="${1:-all}"
	case "$cmd" in
	version) cmd_version ;;
	introspect) cmd_introspect ;;
	capabilities) cmd_capabilities ;;
	all)
		echo "== version"; cmd_version
		echo "== capabilities"; cmd_capabilities
		;;
	-h | --help | help) usage ;;
	*)
		echo "${0##*/}: unknown command '$cmd'" >&2
		usage >&2
		exit 64
		;;
	esac
}

main "$@"
