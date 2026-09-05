#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
#
# trigger-certificate.sh -- poke the PUBLIC Certificate portal interface.
#
# This calls org.freedesktop.portal.experimental.Certificate on
# org.freedesktop.portal.Desktop at /org/freedesktop/portal/desktop -- the
# frontend, never this repository's backend. An application would do exactly
# this, and it is the only way to exercise the backend the way it is meant to be
# exercised.
#
# The interface only exists if the running xdg-desktop-portal was started with
#     XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate
# (or "all"). With the gate off the interface is not exported at all and every
# call below fails with "no such interface" -- which is the intended behaviour,
# not a bug in this script.
#
# It defaults to --session-bus, i.e. whatever DBUS_SESSION_BUS_ADDRESS points
# at. To keep the real desktop out of it, run the whole thing on a private bus:
#
#     dbus-run-session -- tools/trigger-certificate.sh
#
# ...but a private bus has no portal on it, so in practice use
#     tools/dev-stack.sh --keep --no-e2e
# which starts a frontend and a backend on a private bus and leaves them up, and
# then run this from another shell with the DBUS_SESSION_BUS_ADDRESS it printed.
#
# For anything more than poking one method, tools/certificate-e2e.py does the
# whole flow and verifies the signature at the end.
#
# Method and argument shapes are taken from
# data/org.freedesktop.portal.experimental.Certificate.xml on the
# xdg-desktop-portal branch experimental/certificate-webauthentication (commit
# 703fb22) and from that branch's tests/test_certificate.py.

set -u

BUS="${BUS:---session}"          # --session (default) or --system
DEST=org.freedesktop.portal.Desktop
PATH_=/org/freedesktop/portal/desktop
IFACE=org.freedesktop.portal.experimental.Certificate

usage() {
	cat <<EOF
Usage: ${0##*/} [command]

Commands:
  version        read the interface's version property (works with no backend
                 running, as long as the interface is exported)
  introspect     list the experimental interfaces the portal exports
  capabilities   GetCapabilities(a{sv}) -> a{sv}; a plain method, answers directly
  session        CreateSession(a{sv}) -> o handle
                 NOTE: this is a Request. The session_handle comes back in the
                 Response signal on the returned handle, not as a return value.
  acquire PATH   AcquireCredential(o session, s parent_window, a{sv}) -> o handle
  sign PATH      Sign(o session, s parent_window, a{sv}) -> o handle
  renew PATH     RenewGrant(o session, a{sv}) -> t expires_at   (frontend only,
                 no backend call, no window)
  release PATH   ReleaseGrant(o session)
  monitor        watch Request/Session/Certificate signals and exit on Ctrl-C
  all            monitor in the background, then version + capabilities + session

Environment:
  BUS            --session (default) or --system
EOF
}

monitor_bg() {
	# The answer to CreateSession/AcquireCredential/Sign arrives as a Response
	# signal on the Request object, not as the method's return value, so
	# something has to be watching before the call is made.
	gdbus monitor "$BUS" --dest "$DEST" &
	MONITOR_PID=$!
	# Give the monitor a moment to attach before anything is sent.
	sleep 1
}

cmd_version() {
	gdbus call "$BUS" --dest "$DEST" --object-path "$PATH_" \
		--method org.freedesktop.DBus.Properties.Get \
		"$IFACE" version
}

cmd_introspect() {
	gdbus introspect "$BUS" --dest "$DEST" --object-path "$PATH_" |
		grep -i experimental || echo "no experimental interfaces exported"
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
	# purpose is REQUIRED and there is deliberately no value meaning "anything".
	# requested_lifetime is a ceiling request: the frontend clamps it to 3600 and
	# forwards its own decision to the backend as `lifetime`.
	gdbus call "$BUS" --dest "$DEST" --object-path "$PATH_" \
		--method "$IFACE".AcquireCredential \
		"$session" "" \
		"{'handle_token': <'c2'>, \
'purpose': <'client_auth'>, \
'reason': <'Connect to the corporate VPN'>, \
'requested_lifetime': <uint32 600>, \
'interaction_mode': <'allowed'>, \
'allow_selection_memory': <true>}"
}

cmd_sign() {
	local session="$1"
	# mechanism must be one the grant reported in supported_mechanisms; the
	# frontend's allow list is RSA_PKCS1_V1_5, RSA_PSS, ECDSA.
	gdbus call "$BUS" --dest "$DEST" --object-path "$PATH_" \
		--method "$IFACE".Sign \
		"$session" "" \
		"{'handle_token': <'c3'>, \
'mechanism': <'ECDSA'>, \
'operation_id': <'op-1'>, \
'data': <[byte 0x01, 0x02, 0x03]>, \
'parameters': <{'hash': <'SHA256'>}>}"
}

cmd_renew() {
	gdbus call "$BUS" --dest "$DEST" --object-path "$PATH_" \
		--method "$IFACE".RenewGrant "$1" "{'requested_lifetime': <uint32 900>}"
}

cmd_release() {
	gdbus call "$BUS" --dest "$DEST" --object-path "$PATH_" \
		--method "$IFACE".ReleaseGrant "$1"
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
	renew)
		[ $# -ge 2 ] || { echo "renew needs a session object path" >&2; exit 64; }
		cmd_renew "$2"
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
		# The Response is asynchronous; give it a moment to land in the monitor.
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
