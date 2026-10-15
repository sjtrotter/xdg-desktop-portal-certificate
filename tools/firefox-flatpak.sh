#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
# Firefox setup and sandbox verification are documented in docs/TESTING.md.

set -u

here() { cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd; }
REPO="$(here)"
APP=org.mozilla.firefox
MODULE="${MODULE:-$REPO/build/src/module/libpkcs11-portal-certificate.so}"
APPDIR="$HOME/.var/app/$APP"
PROFILE="$APPDIR/portal-profile"
URL=""
FRESH=0
CHECK=0
KEEP_PCSC=0

die() { echo "${0##*/}: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
		--url) URL="$2"; shift ;;
		--module) MODULE="$2"; shift ;;
		--fresh) FRESH=1 ;;
		--check) CHECK=1 ;;
		--keep-pcsc) KEEP_PCSC=1 ;;
		-h | --help)
			cat <<EOF
Usage: ${0##*/} [options]

Run Flatpak Firefox with the Certificate portal module in a test profile.
Start tools/dev-stack.sh --live --keep --no-e2e --pin-prompt=system first.

Options:
  --url URL       open a site requesting a client certificate
  --module PATH   copy this module into the sandbox (overrides MODULE)
  --fresh         remove the test profile before starting Firefox
  --check         check portal and sandbox access without starting Firefox
  --keep-pcsc     retain the sandbox's pcsc socket and device access
  -h, --help      show this help

The default run removes pcsc socket and device access.
Firefox requires manual module loading through Settings, Privacy & Security,
Security Devices, Load. The module path is printed when Firefox starts.
EOF
			exit 0 ;;
		*) die "unknown option $1" ;;
	esac
	shift
done

command -v flatpak >/dev/null || die "flatpak not found"
flatpak info "$APP" >/dev/null 2>&1 || die "$APP is not installed: flatpak install flathub $APP"
[ -f "$MODULE" ] || die "no module at $MODULE; build the repository first or set MODULE"

# A user-local RPM launcher outranks the Flatpak export with the same desktop ID.
if [ -f /usr/share/applications/$APP.desktop ] && [ ! -f "$HOME/.local/share/applications/$APP.desktop" ]; then
	mkdir -p "$HOME/.local/share/applications"
	cp /usr/share/applications/$APP.desktop "$HOME/.local/share/applications/$APP.desktop"
	update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
	echo "${0##*/}: kept the host Firefox launcher ahead of the Flatpak's ($HOME/.local/share/applications/$APP.desktop)"
fi

if ! gdbus introspect --session --dest org.freedesktop.portal.Desktop \
	--object-path /org/freedesktop/portal/desktop 2>/dev/null |
	grep -q "org.freedesktop.portal.experimental.Certificate1"; then
	die "the session's xdg-desktop-portal does not export the Certificate interface; run tools/dev-stack.sh --live --keep --no-e2e --pin-prompt=system first"
fi
if ! busctl --user list 2>/dev/null | grep -q "org.freedesktop.impl.portal.desktop.certificate"; then
	echo "${0##*/}: Backend service has no owner; start tools/dev-stack.sh --live" >&2
fi

RUN_ARGS=(--env=PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1)
if [ "$KEEP_PCSC" = 0 ]; then
	RUN_ARGS+=(--nosocket=pcsc --nodevice=all)
fi

if flatpak run "${RUN_ARGS[@]}" --command=sh "$APP" -c 'test -e /run/pcscd' 2>/dev/null; then
	echo "${0##*/}: pcsc socket: open in the sandbox"
	[ "$KEEP_PCSC" = 1 ] || die "expected --nosocket=pcsc to remove /run/pcscd"
else
	echo "${0##*/}: pcsc socket: closed in the sandbox"
fi
flatpak run "${RUN_ARGS[@]}" --command=gdbus "$APP" introspect --session \
	--dest org.freedesktop.portal.Desktop \
	--object-path /org/freedesktop/portal/desktop 2>/dev/null |
	grep -q "org.freedesktop.portal.experimental.Certificate1" ||
	die "the sandbox cannot see the Certificate interface on the portal bus"
echo "${0##*/}: portal bus: Certificate interface visible from the sandbox"

[ "$CHECK" = 1 ] && exit 0

mkdir -p "$APPDIR/data"
cp -f "$MODULE" "$APPDIR/data/"
INSIDE="$APPDIR/data/libpkcs11-portal-certificate.so"
if [ "$FRESH" = 1 ]; then
	rm -rf "$PROFILE"
fi
mkdir -p "$PROFILE"

cat <<MSG
${0##*/}: module copied to $INSIDE
${0##*/}: profile $PROFILE
${0##*/}: in Firefox, once per profile:
    Settings -> Privacy & Security -> Security Devices -> Load
    Module name: Portal Certificate
    Module filename: $INSIDE
${0##*/}: then visit a site that asks for a client certificate.
${0##*/}: expect: this backend's chooser, Firefox's picker, the shell's PIN prompt.
MSG

exec flatpak run "${RUN_ARGS[@]}" "$APP" --new-instance --profile "$PROFILE" ${URL:+"$URL"}
