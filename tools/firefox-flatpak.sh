#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
#
# firefox-flatpak.sh -- Firefox from Flathub, signing in with the card through
# the portal, with the sandbox's pcsc socket and device access taken away.
#
# The Flathub Firefox ships with sockets=pcsc and devices=all, so out of the
# box it can reach pcscd directly. This run removes both, so the only route to
# the card is the PKCS#11 module -> D-Bus -> xdg-desktop-portal -> this backend.
#
# Needs the live stack first, in another terminal:
#
#     tools/dev-stack.sh --live --keep --no-e2e --pin-prompt=system
#
# --no-e2e skips the stack's own self-test, which with a card present is a
# chooser and a PIN prompt before Firefox has started.
#
# Then:
#
#     tools/firefox-flatpak.sh                  # copies the module, opens Firefox
#     tools/firefox-flatpak.sh --url https://...# and a site that asks for a certificate
#     tools/firefox-flatpak.sh --fresh          # throw the test profile away first
#     tools/firefox-flatpak.sh --keep-pcsc      # control run: sandbox as shipped
#     tools/firefox-flatpak.sh --check          # preflight only
#
# One manual step remains, once per profile: Settings -> Privacy & Security ->
# Security Devices -> Load, path printed below. Firefox loads the .so directly
# and does not read p11-kit configuration.
#
# The proof is on the dev-stack terminal: the backend's decision line carries
# app_id=org.mozilla.firefox identity=sandboxed, and the frontend log in
# $DEVDIR has the matching CreateSession/AcquireCredential. Expect three
# dialogs: this backend's chooser, Firefox's own picker, the shell's PIN prompt.

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
		-h | --help) sed -n '5,32p' "$0"; exit 0 ;;
		*) die "unknown option $1" ;;
	esac
	shift
done

command -v flatpak >/dev/null || die "flatpak not found"
flatpak info "$APP" >/dev/null 2>&1 || die "$APP is not installed: flatpak install flathub $APP"
[ -f "$MODULE" ] || die "no module at $MODULE; build the repository first or set MODULE"

# The Flatpak exports org.mozilla.firefox.desktop and the user export directory
# precedes /usr/share in XDG_DATA_DIRS. Fedora's RPM Firefox ships the same id,
# so installing the Flatpak silently repoints the dock icon and the default
# browser at the Flatpak and its empty profile. A copy of the RPM launcher in
# XDG_DATA_HOME outranks both; this run never goes through the launcher anyway.
if [ -f /usr/share/applications/$APP.desktop ] && [ ! -f "$HOME/.local/share/applications/$APP.desktop" ]; then
	mkdir -p "$HOME/.local/share/applications"
	cp /usr/share/applications/$APP.desktop "$HOME/.local/share/applications/$APP.desktop"
	update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
	echo "${0##*/}: kept the host Firefox launcher ahead of the Flatpak's ($HOME/.local/share/applications/$APP.desktop)"
fi

# The session's portal must be the branch build with this backend configured
# behind it. gdbus is used from the host: the interface list is the same one the
# sandbox sees.
if ! gdbus introspect --session --dest org.freedesktop.portal.Desktop \
	--object-path /org/freedesktop/portal/desktop/experimental 2>/dev/null |
	grep -q "org.freedesktop.portal.Certificate.X1"; then
	die "the session's xdg-desktop-portal does not export the Certificate interface; run tools/dev-stack.sh --live --keep --no-e2e --pin-prompt=system first"
fi
if ! busctl --user list 2>/dev/null | grep -q "org.freedesktop.impl.portal.desktop.certificate"; then
	echo "${0##*/}: warning: no backend owns org.freedesktop.impl.portal.desktop.certificate; is dev-stack --live up?" >&2
fi

RUN_ARGS=(--env=PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1)
if [ "$KEEP_PCSC" = 0 ]; then
	RUN_ARGS+=(--nosocket=pcsc --nodevice=all)
fi

# What the sandbox will and will not see, before Firefox is started.
if flatpak run "${RUN_ARGS[@]}" --command=sh "$APP" -c 'test -e /run/pcscd' 2>/dev/null; then
	echo "${0##*/}: pcsc socket: OPEN in the sandbox"
	[ "$KEEP_PCSC" = 1 ] || die "expected --nosocket=pcsc to remove /run/pcscd"
else
	echo "${0##*/}: pcsc socket: closed in the sandbox"
fi
flatpak run "${RUN_ARGS[@]}" --command=gdbus "$APP" introspect --session \
	--dest org.freedesktop.portal.Desktop \
	--object-path /org/freedesktop/portal/desktop/experimental 2>/dev/null |
	grep -q "org.freedesktop.portal.Certificate.X1" ||
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
