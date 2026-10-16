#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
# Create isolated software credentials with test PIN 123456; see docs/TESTING.md for setup and hardware coverage.

set -eu

SOFTHSM_DIR="${SOFTHSM_DIR:-${TMPDIR:-/tmp}/xdp-certificate-softhsm}"
PIN="${PIN:-123456}"
SO_PIN="${SO_PIN:-3737}"

die() {
	echo "${0##*/}: $*" >&2
	exit 40
}

# shellcheck source=tools/lib.sh
. "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

find_module() {
	if [ -n "${SOFTHSM_MODULE:-}" ]; then
		echo "$SOFTHSM_MODULE"
		return
	fi

	for candidate in \
		/usr/lib64/pkcs11/libsofthsm2.so \
		/usr/lib64/softhsm/libsofthsm2.so \
		/usr/lib/softhsm/libsofthsm2.so \
		/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so; do
		[ -f "$candidate" ] && {
			echo "$candidate"
			return
		}
	done

	die "libsofthsm2.so not found; install softhsm or set SOFTHSM_MODULE"
}

find_util() {
	if command -v softhsm2-util >/dev/null; then
		command -v softhsm2-util
		return
	fi

	candidate="$(dirname "$(dirname "$(dirname "$1")")")/bin/softhsm2-util"
	[ -x "$candidate" ] && {
		echo "$candidate"
		return
	}

	die "softhsm2-util not found; set PATH or unpack it next to the module"
}

if [ "${1:-}" = "--clean" ]; then
	fixture_remove "$SOFTHSM_DIR" softhsm
	echo "removed $SOFTHSM_DIR"
	exit 0
fi

command -v certtool >/dev/null || die "certtool not found (gnutls-utils)"
command -v pkcs11-tool >/dev/null || die "pkcs11-tool not found (opensc)"
command -v openssl >/dev/null || die "openssl not found"

MODULE="$(find_module)"
UTIL="$(find_util "$MODULE")"

fixture_remove "$SOFTHSM_DIR" softhsm

# Create private-key directories with mode 0700 from the outset.
fixture_make "$SOFTHSM_DIR" softhsm
(umask 077 && mkdir -p "$SOFTHSM_DIR/tokens")

cat >"$SOFTHSM_DIR/softhsm2.conf" <<EOF
directories.tokendir = $SOFTHSM_DIR/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF

printf '%s' "$MODULE" >"$SOFTHSM_DIR/module-path"

export SOFTHSM2_CONF="$SOFTHSM_DIR/softhsm2.conf"

LABEL="Portal Test Token"
"$UTIL" --module "$MODULE" --init-token --slot 0 --label "$LABEL" \
	--so-pin "$SO_PIN" --pin "$PIN" >/dev/null

make_key() {
	name="$1"
	id="$2"
	keyargs="$3"
	template="$4"

	printf '%s\n' "$template" >"$SOFTHSM_DIR/$name.tmpl"
	# shellcheck disable=SC2086
	certtool --generate-privkey $keyargs --outfile "$SOFTHSM_DIR/$name.key" 2>/dev/null
	certtool --generate-self-signed --load-privkey "$SOFTHSM_DIR/$name.key" \
		--template "$SOFTHSM_DIR/$name.tmpl" --outfile "$SOFTHSM_DIR/$name.pem" 2>/dev/null
	openssl x509 -in "$SOFTHSM_DIR/$name.pem" -outform der -out "$SOFTHSM_DIR/$name.der"

	# softhsm2-util requires PKCS#8; certtool emits PKCS#1 for RSA and SEC1 for EC.
	openssl pkcs8 -topk8 -nocrypt -in "$SOFTHSM_DIR/$name.key" \
		-out "$SOFTHSM_DIR/$name.p8"
	# Only fixture PINs may appear in argv for these import tools.
	"$UTIL" --module "$MODULE" --import "$SOFTHSM_DIR/$name.p8" --token "$LABEL" \
		--label "$name" --id "$id" --pin "$PIN" >/dev/null

	pkcs11-tool --module "$MODULE" --token-label "$LABEL" --login --pin "$PIN" \
		--write-object "$SOFTHSM_DIR/$name.der" --type cert --id "$id" --label "$name" >/dev/null

	rm -f "$SOFTHSM_DIR/$name.key" "$SOFTHSM_DIR/$name.p8" "$SOFTHSM_DIR/$name.tmpl"
}

# CKA_ID 01 exercises OpenSC's PIV authentication-slot mapping.
make_key portal-test-rsa 01 "--key-type=rsa --bits=2048" 'organization = "Example Org"
cn = "Portal Test User (RSA)"
serial = 011
expiration_days = 3650
signing_key
encryption_key
tls_www_client
email_protection_key'

make_key portal-test-ec 02 "--key-type=ecdsa --curve=secp256r1" 'organization = "Example Org"
cn = "Portal Test User (EC)"
serial = 012
expiration_days = 3650
signing_key
tls_www_client'

cat <<EOF

SoftHSM fixture ready.

  directory   $SOFTHSM_DIR
  module      $MODULE
  token       $LABEL
  PIN         $PIN   (a test PIN in a scratch directory; do not reuse it)

Point the backend at it:

  export SOFTHSM2_CONF=$SOFTHSM_DIR/softhsm2.conf
  ./build/src/xdg-desktop-portal-certificate --module $MODULE --list-tokens

Or run the whole stack against it:

  tools/dev-stack.sh --softhsm -- --purpose client_auth
EOF
