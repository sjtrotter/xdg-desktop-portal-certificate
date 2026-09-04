#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# softhsm-fixture.sh -- build a SoftHSM token holding an RSA and an EC key, each
# with a self-signed certificate, so that the whole path can be rehearsed
# without a card: chooser, PIN prompt, C_Login, C_Sign, verification.
#
# A TEST THAT HAS ONLY BEEN RUN AGAINST A SOFTWARE TOKEN HAS NOT BEEN RUN. This
# is the rehearsal. The Remmina work this project builds on found every one of
# its edge cases on hardware and none of them was predictable from the
# specification; docs/TESTING.md is the list of things only a card can answer.
#
#     tools/softhsm-fixture.sh              # create it
#     tools/softhsm-fixture.sh --clean      # remove it
#
# It writes a self-contained token directory that nothing else on the machine
# sees, because SOFTHSM2_CONF points at a config inside it. The PIN is 123456
# and it is a test PIN in a scratch directory; do not reuse it anywhere.
#
#   $SOFTHSM_DIR     where to put it. Default ${TMPDIR:-/tmp}/xdp-certificate-softhsm
#   $SOFTHSM_MODULE  path to libsofthsm2.so. Searched for if unset.
#
# THE DIRECTORY IS CHECKED BEFORE IT IS USED. The default path is predictable
# and it has to be -- tests/test-broker-device.c and tools/dev-stack.sh both
# look for it there -- and what lives in it is a file the BACKEND dlopen()s:
# $SOFTHSM_DIR/module-path is passed to --module. On a machine with a shared
# sticky /tmp another user can create that directory first, so this refuses to
# touch anything that is a symlink, is not a directory, is not owned by this
# user, or is group- or world-writable, rather than writing the fixture into
# somebody else's directory.

set -eu

SOFTHSM_DIR="${SOFTHSM_DIR:-${TMPDIR:-/tmp}/xdp-certificate-softhsm}"
PIN="${PIN:-123456}"
SO_PIN="${SO_PIN:-3737}"

die() {
	echo "${0##*/}: $*" >&2
	exit 40
}

# Refuse anything we do not own outright. See the header.
check_dir() {
	local path="$1" owner mode

	# The two that cannot be repaired: somebody else's directory, or a link into
	# one. Both mean the fixture -- and the module the backend dlopen()s out of
	# it -- would be under someone else's control.
	[ -L "$path" ] && die "$path is a symlink; refusing to use it"
	[ -d "$path" ] || die "$path exists and is not a directory"

	owner="$(stat -c %u "$path")"
	[ "$owner" = "$(id -u)" ] || die "$path is owned by uid $owner, not $(id -u)"

	# The one that can: we own it, so tighten it rather than refusing to work.
	mode="$(stat -c %a "$path")"
	case "$mode" in
	700 | 500) ;;
	*)
		echo "${0##*/}: tightening $path from mode $mode to 700" >&2
		chmod 700 "$path" || die "could not chmod $path"
		;;
	esac
}

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

	die "libsofthsm2.so not found. Install softhsm, or set SOFTHSM_MODULE.
Without root, 'dnf download softhsm' and 'rpm2cpio ... | cpio -idmu' into a
scratch directory is enough: nothing here needs the package installed."
}

find_util() {
	if command -v softhsm2-util >/dev/null; then
		command -v softhsm2-util
		return
	fi

	# Alongside the module, in an unpacked-rpm layout.
	candidate="$(dirname "$(dirname "$(dirname "$1")")")/bin/softhsm2-util"
	[ -x "$candidate" ] && {
		echo "$candidate"
		return
	}

	die "softhsm2-util not found; set PATH or unpack it next to the module"
}

if [ "${1:-}" = "--clean" ]; then
	if [ -e "$SOFTHSM_DIR" ]; then
		check_dir "$SOFTHSM_DIR"
		rm -rf -- "$SOFTHSM_DIR"
	fi
	echo "removed $SOFTHSM_DIR"
	exit 0
fi

command -v certtool >/dev/null || die "certtool not found (gnutls-utils)"
command -v pkcs11-tool >/dev/null || die "pkcs11-tool not found (opensc)"
command -v openssl >/dev/null || die "openssl not found"

MODULE="$(find_module)"
UTIL="$(find_util "$MODULE")"

if [ -e "$SOFTHSM_DIR" ]; then
	check_dir "$SOFTHSM_DIR"
	rm -rf -- "$SOFTHSM_DIR"
fi

# 700 from the moment it exists, not after: the token files hold the fixture's
# private keys, and a window in which they are world-readable is a window.
(umask 077 && mkdir -p "$SOFTHSM_DIR/tokens")
check_dir "$SOFTHSM_DIR"

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

	# softhsm2-util imports PKCS#8 only, and certtool writes PKCS#1 for RSA and
	# SEC1 for EC. Converting is one openssl call and beats guessing.
	openssl pkcs8 -topk8 -nocrypt -in "$SOFTHSM_DIR/$name.key" \
		-out "$SOFTHSM_DIR/$name.p8"
	# softhsm2-util and pkcs11-tool take the PIN on argv and offer no other way,
	# so it is visible in ps for the length of these two calls. THAT IS ONLY
	# ACCEPTABLE BECAUSE THIS IS A THROWAWAY FIXTURE PIN in a scratch directory.
	# Nothing that touches a real card may copy this pattern; tools/ui-smoke.sh
	# passes its PIN through the environment for exactly that reason.
	"$UTIL" --module "$MODULE" --import "$SOFTHSM_DIR/$name.p8" --token "$LABEL" \
		--label "$name" --id "$id" --pin "$PIN" >/dev/null

	pkcs11-tool --module "$MODULE" --token-label "$LABEL" --login --pin "$PIN" \
		--write-object "$SOFTHSM_DIR/$name.der" --type cert --id "$id" --label "$name" >/dev/null

	rm -f "$SOFTHSM_DIR/$name.key" "$SOFTHSM_DIR/$name.p8" "$SOFTHSM_DIR/$name.tmpl"
}

# CKA_ID 01 is what OpenSC's PIV driver uses for the authentication slot, so the
# fixture exercises the piv_slot mapping as well.
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
