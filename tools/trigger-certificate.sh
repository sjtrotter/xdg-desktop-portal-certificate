#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
# Calls targeting Certificate1 fail when it is not exported; introspect can still list other interfaces at the shared object path.

set -u

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
  session        CreateSession(a{sv}) -> o handle
                 session_handle arrives in the Request's Response signal
  acquire PATH   AcquireCredential(o session, s parent_window, a{sv}) -> o handle
  sign PATH      Sign(o session, s parent_window, a{sv}) -> o handle
  release PATH   Session.Close(); a grant ends with its session
  monitor        watch Request/Session/Certificate signals and exit on Ctrl-C
  all            monitor in the background, then version + capabilities + session

Environment:
  BUS            --session (default) or --system
EOF
}

monitor_bg() {
	# Subscribe before calling so asynchronous Response signals are observed.
	gdbus monitor "$BUS" --dest "$DEST" &
	MONITOR_PID=$!
	sleep 1
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

cmd_session() {
	gdbus call "$BUS" --dest "$DEST" --object-path "$PATH_" \
		--method "$IFACE".CreateSession \
		"{'handle_token': <'c1'>, 'session_handle_token': <'s1'>}"
}

cmd_acquire() {
	local session="$1"
	# The frontend caps requested_lifetime at 3600 seconds and forwards its decision as lifetime.
	gdbus call "$BUS" --dest "$DEST" --object-path "$PATH_" \
		--method "$IFACE".AcquireCredential \
		"$session" "" \
		"{'handle_token': <'c2'>, \
'purpose': <'client_auth'>, \
'reason': <'Connect to the corporate VPN'>, \
'requested_lifetime': <uint32 600>, \
'interaction_mode': <'allowed'>}"
}

cmd_sign() {
	local session="$1"
	gdbus call "$BUS" --dest "$DEST" --object-path "$PATH_" \
		--method "$IFACE".Sign \
		"$session" "" \
		"{'handle_token': <'c3'>, \
'mechanism': <'ECDSA'>, \
'operation_id': <'op-1'>, \
'data': <[byte 0x01, 0x02, 0x03]>, \
'parameters': <{'hash': <'SHA256'>}>}"
}

cmd_release() {
	gdbus call "$BUS" --dest "$DEST" --object-path "$1" \
		--method org.freedesktop.portal.Session.Close
}

main() {
	local cmd="${1:-all}"
	case "$cmd" in
	version) cmd_version ;;
	introspect) cmd_introspect ;;
	capabilities) cmd_capabilities ;;
	session) cmd_session ;;
	acquire)
		[ $# -ge 2 ] || { echo "acquire needs a session object path" >&2; exit 64; }
		cmd_acquire "$2"
		;;
	sign)
		[ $# -ge 2 ] || { echo "sign needs a session object path" >&2; exit 64; }
		cmd_sign "$2"
		;;
	release)
		[ $# -ge 2 ] || { echo "release needs a session object path" >&2; exit 64; }
		cmd_release "$2"
		;;
	monitor) gdbus monitor "$BUS" --dest "$DEST" ;;
	all)
		monitor_bg
		trap 'kill "$MONITOR_PID" 2>/dev/null' EXIT
		echo "== version"; cmd_version
		echo "== capabilities"; cmd_capabilities
		echo "== CreateSession"
		cmd_session
		sleep 2
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
