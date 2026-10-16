#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
# Chrome setup and sandbox verification are documented in docs/TESTING.md.

set -u

here() { cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd; }
REPO="$(here)"
APP=com.google.Chrome
MODULE="${MODULE:-$REPO/build/src/module/libpkcs11-portal-certificate.so}"
APPDIR="$HOME/.var/app/$APP"
INSIDE="$APPDIR/data/libpkcs11-portal-certificate.so"
MODUTIL="${MODUTIL:-modutil}"
MODULE_NAME="Portal Certificate"
POLICY_DIR=/etc/opt/chrome/policies/managed
URL=""
SITE='https://[*.]example.org'
PRINT_POLICY=0
CHECK=0
KEEP_PCSC=0
KEEP_DEVICES=0

die() { echo "${0##*/}: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
		--url | --module | --site)
			[ $# -ge 2 ] && [ -n "$2" ] || die "$1 requires a value"
			case "$1" in
				--url) URL="$2" ;;
				--module) MODULE="$2" ;;
				--site) SITE="$2"; PRINT_POLICY=1 ;;
			esac
			shift ;;
		--check) CHECK=1 ;;
		--keep-pcsc) KEEP_PCSC=1 ;;
		--keep-devices) KEEP_DEVICES=1 ;;
		-h | --help)
			cat <<EOF
Usage: ${0##*/} [options]

Run Flatpak Chrome with the Certificate portal module registered in NSS.
Start tools/dev-stack.sh --live --keep --no-e2e --pin-prompt=system first.
Start Chrome once to create its profile, then close every Chrome window.

Options:
  --url URL       open a site requesting a client certificate
  --module PATH   copy this module into the sandbox (overrides MODULE)
  --check         verify setup without copying, registering or starting Chrome
  --keep-pcsc     retain the sandbox's pcsc socket and device access
  --keep-devices  retain device access if --nodevice=all prevents GPU startup
  --site PATTERN  print policy installation commands for this URL pattern
  -h, --help      show this help

The default run removes pcsc socket and device access.
MODUTIL selects modutil; otherwise it must be on PATH (package: nss-tools).
Missing policy output uses https://[*.]example.org unless --site is given.
Policy commands are printed for manual installation; sudo is never run.
EOF
			exit 0 ;;
		*) die "unknown option $1" ;;
	esac
	shift
done

[[ "$SITE" != *[[:cntrl:]]* ]] || die "site pattern must not contain control characters"
command -v flatpak >/dev/null || die "flatpak not found"
command -v "$MODUTIL" >/dev/null || die "modutil not found; install nss-tools or set MODUTIL=/path/to/modutil"
flatpak info "$APP" >/dev/null 2>&1 || die "$APP is not installed: flatpak install flathub $APP"
[ -f "$MODULE" ] || die "no module at $MODULE; build the repository first or set MODULE"
if flatpak ps --columns=application 2>/dev/null | grep -qx "$APP"; then
	die "Chrome is running; quit it completely (flatpak kill $APP) before setup"
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
	RUN_ARGS+=(--nosocket=pcsc)
	if [ "$KEEP_DEVICES" = 0 ]; then
		RUN_ARGS+=(--nodevice=all)
	fi
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

[ -d "$APPDIR" ] || die "start Chrome once to create its profile"
mapfile -d '' -t DATABASES < <(find "$APPDIR" -type f -name cert9.db -print0)
[ "${#DATABASES[@]}" -gt 0 ] || die "start Chrome once to create its profile"
if [ "${#DATABASES[@]}" -ne 1 ]; then
	for database in "${DATABASES[@]}"; do
		echo "${0##*/}: NSS database: $database" >&2
	done
	die "multiple NSS databases found under $APPDIR; identify Chrome's active database before setup"
fi
DBDIR="${DATABASES[0]%/cert9.db}"
echo "${0##*/}: NSS database: $DBDIR"

if [ "$CHECK" = 0 ]; then
	mkdir -p "$APPDIR/data" || die "module directory could not be created: $APPDIR/data"
	cp -f "$MODULE" "$INSIDE" || die "module could not be copied to $INSIDE"
	echo "${0##*/}: module copied to $INSIDE"
else
	[ -f "$INSIDE" ] || die "module missing at $INSIDE; run without --check to copy it"
fi

flatpak run "${RUN_ARGS[@]}" --command=sh "$APP" -c 'test -r "$1" && test -r "$2"' \
	sh "$INSIDE" "$DBDIR/cert9.db" || die "module or NSS database is unreadable at its sandbox path"
echo "${0##*/}: sandbox paths: module and NSS database readable"

LIST=$("$MODUTIL" -dbdir "sql:$DBDIR" -list </dev/null) || die "NSS module list failed; close Chrome and check $DBDIR"
if printf '%s\n' "$LIST" | grep -Fq -- "$MODULE_NAME"; then
	DETAIL=$("$MODUTIL" -dbdir "sql:$DBDIR" -list "$MODULE_NAME" </dev/null) || die "NSS module details failed"
	printf '%s\n' "$DETAIL" | grep -Fq -- "$INSIDE" ||
		die "NSS module $MODULE_NAME uses another library; inspect it with modutil before setup"
else
	[ "$CHECK" = 0 ] || die "NSS module missing; run without --check to register it"
	"$MODUTIL" -dbdir "sql:$DBDIR" -add "$MODULE_NAME" -libfile "$INSIDE" -force </dev/null ||
		die "NSS module registration failed; close Chrome and check $DBDIR"
fi
echo "${0##*/}: NSS module: $MODULE_NAME registered at $INSIDE"

POLICY_FOUND=0
if grep -rq 'AutoSelectCertificateForUrls' "$POLICY_DIR" 2>/dev/null; then
	POLICY_FOUND=1
	echo "${0##*/}: policy: AutoSelectCertificateForUrls found; confirm the pattern in chrome://policy"
else
	echo "${0##*/}: policy: AutoSelectCertificateForUrls missing; install the printed example before testing automatic selection"
fi

if [ "$POLICY_FOUND" = 0 ] || [ "$PRINT_POLICY" = 1 ]; then
	PATTERN_JSON=${SITE//\\/\\\\}
	PATTERN_JSON=${PATTERN_JSON//\"/\\\"}
	ENTRY="{\"pattern\":\"$PATTERN_JSON\",\"filter\":{}}"
	ENTRY_JSON=${ENTRY//\\/\\\\}
	ENTRY_JSON=${ENTRY_JSON//\"/\\\"}
	cat <<EOF
${0##*/}: policy installation: run these commands on the host after reviewing the pattern
sudo install -d -m 0755 $POLICY_DIR
sudo tee $POLICY_DIR/portal-certificate.json >/dev/null <<'POLICY'
{
  "AutoSelectCertificateForUrls": [
    "$ENTRY_JSON"
  ]
}
POLICY
sudo chmod 0644 $POLICY_DIR/portal-certificate.json
EOF
fi

if [ "$CHECK" = 1 ]; then
	[ "$POLICY_FOUND" = 1 ] || exit 1
	exit 0
fi

echo "${0##*/}: module path in the sandbox: $INSIDE"
echo "${0##*/}: matching policy: expect the portal chooser and portal PIN prompt without Chrome's picker"
exec flatpak run "${RUN_ARGS[@]}" "$APP" ${URL:+"$URL"}
