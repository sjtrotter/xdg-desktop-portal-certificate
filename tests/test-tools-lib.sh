#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>

set -u

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

failures=0
checks=0

ok() {
	checks=$((checks + 1))
	echo "ok $checks - $1"
}

not_ok() {
	checks=$((checks + 1))
	failures=$((failures + 1))
	echo "not ok $checks - $1"
	shift
	printf '#   %s\n' "$@"
}

expect_eq() {
	local what="$1" want="$2" got="$3"

	if [ "$want" = "$got" ]; then
		ok "$what"
	else
		not_ok "$what" "expected: $want" "     got: $got"
	fi
}

expect_line() {
	local what="$1" file="$2" line="$3"

	if grep -qxF -- "$line" "$file"; then
		ok "$what"
	else
		not_ok "$what" "no line '$line' in $file" "$(sed 's/^/    /' "$file")"
	fi
}

expect_no_line() {
	local what="$1" file="$2" pattern="$3"

	if grep -q -- "$pattern" "$file"; then
		not_ok "$what" "'$pattern' is still in $file" "$(sed 's/^/    /' "$file")"
	else
		ok "$what"
	fi
}

# Refusal exits 40, so run it in a subshell.
expect_refused() {
	local what="$1"
	shift
	local output status

	output="$("$@" 2>&1)"
	status=$?

	if [ "$status" -eq 0 ]; then
		not_ok "$what" "it was accepted; output: $output"
	else
		ok "$what"
	fi
}

expect_accepted() {
	local what="$1"
	shift
	local output status

	output="$("$@" 2>&1)"
	status=$?

	if [ "$status" -eq 0 ]; then
		ok "$what"
	else
		not_ok "$what" "it was refused: $output"
	fi
}

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/xdp-certificate-libtest.XXXXXXXX")" || exit 99
trap 'rm -rf --one-file-system -- "$ROOT"' EXIT

# Use an isolated TMPDIR so fixture tests cannot reach the user's scratch directories.
export TMPDIR="$ROOT/tmp"
mkdir -p "$TMPDIR"

# shellcheck source=tools/lib.sh
. "$REPO/tools/lib.sh"

echo "TAP version 13"

conf_dir() {
	local dir="$1"

	mkdir -p "$dir/xdg-desktop-portal"
	printf '%s' "$dir/xdg-desktop-portal"
}

CHAIN_HOME="$(conf_dir "$ROOT/config-home")"
CHAIN_ETC="$(conf_dir "$ROOT/etc")"

cat >"$CHAIN_HOME/portals.conf" <<'EOF'
[preferred]
org.freedesktop.impl.portal.Screenshot=none;
org.freedesktop.impl.portal.experimental.Certificate1=somethingelse;
EOF

cat >"$CHAIN_ETC/portals.conf" <<'EOF'
[preferred]
default=gnome;
org.freedesktop.impl.portal.Access=gtk;
org.freedesktop.impl.portal.Screenshot=gnome;
EOF

export XDG_CONFIG_HOME="$ROOT/config-home"
export XDG_CONFIG_DIRS="$ROOT/etc"
export XDG_DATA_HOME="$ROOT/data-home"
export XDG_DATA_DIRS="$ROOT/data-dirs"
export XDG_CURRENT_DESKTOP=dev

expect_eq "the chain is both files, user configuration first" \
	"$CHAIN_HOME/portals.conf $CHAIN_ETC/portals.conf" \
	"$(xdp_config_chain | tr '\n' ' ' | sed 's/ $//')"

FLAT="$ROOT/flat.conf"
xdp_flatten_preferred "$CHAIN_HOME/portals.conf" "$CHAIN_ETC/portals.conf" >"$FLAT"

expect_line "a user 'none' beats a later backend for the same interface" \
	"$FLAT" "org.freedesktop.impl.portal.Screenshot=none;"

expect_line "an interface named only in /etc keeps its list and then the default" \
	"$FLAT" "org.freedesktop.impl.portal.Access=gtk;gnome;"

expect_line "the default carries through" "$FLAT" "default=gnome;"

mkdir -p "$ROOT/data-home/xdg-desktop-portal/portals"
DEVDIR="$ROOT/devdir"
mkdir -p "$DEVDIR"

xdp_write_portal_dir "$DEVDIR" "$REPO" private 2>/dev/null

expect_line "the Certificate line names this backend" \
	"$DEVDIR/portals.conf" "org.freedesktop.impl.portal.experimental.Certificate1=certificate;"

expect_no_line "Certificate backend configuration is replaced" \
	"$DEVDIR/portals.conf" "org.freedesktop.impl.portal.experimental.Certificate1=somethingelse"

expect_line "a private run switches the Secret backend off" \
	"$DEVDIR/portals.conf" "org.freedesktop.impl.portal.Secret=none;"

expect_line "the user's Screenshot=none survives into the generated file" \
	"$DEVDIR/portals.conf" "org.freedesktop.impl.portal.Screenshot=none;"

rm -f "$DEVDIR/portals.conf"
xdp_write_portal_dir "$DEVDIR" "$REPO" live 2>/dev/null

expect_no_line "a live run leaves the Secret backend alone" \
	"$DEVDIR/portals.conf" "^org.freedesktop.impl.portal.Secret="

GOOD="$(fixture_mktemp xdp-certificate-libtest-good libtest)"
expect_accepted "a fixture this library made passes" fixture_check "$GOOD" libtest
expect_refused "a fixture checked under the wrong tag is refused" \
	fixture_check "$GOOD" someothertag

UNMARKED="$TMPDIR/unmarked"
mkdir -p "$UNMARKED"
expect_refused "a directory with no marker is refused" fixture_check "$UNMARKED" libtest

FORGED="$TMPDIR/forged"
mkdir -p "$FORGED"
chmod 700 "$FORGED"
ln -s /etc/hostname "$FORGED/$XDP_FIXTURE_MARKER"
expect_refused "a marker that is a symlink is refused" fixture_check "$FORGED" libtest
rm -f "$FORGED/$XDP_FIXTURE_MARKER"

printf 'libtest\n' >"$FORGED/$XDP_FIXTURE_MARKER"
chmod 644 "$FORGED/$XDP_FIXTURE_MARKER"
expect_refused "a world-readable marker is refused" fixture_check "$FORGED" libtest
chmod 600 "$FORGED/$XDP_FIXTURE_MARKER"
expect_accepted "the same marker at 0600 passes" fixture_check "$FORGED" libtest

chmod 755 "$FORGED"
expect_refused "Fixture with mode 0755 is refused" \
	fixture_check "$FORGED" libtest
chmod 700 "$FORGED"

LINKED="$TMPDIR/linked"
ln -s "$GOOD" "$LINKED"
expect_refused "a fixture reached through a symlink is refused" fixture_check "$LINKED" libtest

VIA="$TMPDIR/via"
mkdir -p "$VIA"
ln -s "$GOOD" "$VIA/inside"
expect_refused "a symlink anywhere on the path is refused" fixture_check "$VIA/inside" libtest

expect_refused "a path outside TMPDIR is refused" fixture_check "$ROOT/devdir" libtest

expect_refused "fixture_create refuses to adopt a directory that exists" \
	fixture_create "$UNMARKED" libtest

expect_accepted "fixture_remove deletes a fixture it validated" \
	fixture_remove "$GOOD" libtest
expect_eq "Removed fixture no longer exists" "gone" "$([ -e "$GOOD" ] && echo present || echo gone)"

expect_refused "fixture_remove refuses a directory it did not make" \
	fixture_remove "$UNMARKED" libtest

# Fake consumers exercise phase 0 without loading a module or starting services.
ENUM_LOG="$ROOT/enumeration"
mkdir -p "$ENUM_LOG/stack/document-portal" "$ENUM_LOG/stack/desktop-portal"
for executable in "$ENUM_LOG/stack/document-portal/xdg-permission-store" \
	"$ENUM_LOG/stack/desktop-portal/xdg-desktop-portal" "$ENUM_LOG/driver.sh"; do
	printf '#!/bin/sh\nexit 0\n' >"$executable"
	chmod +x "$executable"
done
P11_STATUS=2
P11_OUTPUT="No matching objects found"
PKCS11_STATUS=0
PKCS11_OUTPUT=""
SHOW_CHOOSER=0

timeout() {
	shift
	case "$1" in
	p11tool)
		if [ "$SHOW_CHOOSER" = 1 ]; then
			echo 'chooser-shown app_id=test' >>"$ENUM_LOG/backend.log"
		fi
		printf '%s\n' "$P11_OUTPUT"
		return "$P11_STATUS"
		;;
	pkcs11-tool)
		printf '%s\n' "$PKCS11_OUTPUT"
		return "$PKCS11_STATUS"
		;;
	*) return 99 ;;
	esac
}

module_phase_zero() (
	local LOGDIR="$ENUM_LOG" XDP_BUILD="$ENUM_LOG/stack" BACKEND_KIND=test
	local MODULE_SO=/unused/module URI_TOKEN=pkcs11:test BE=unused
	# Load the runner without its display and service setup.
	. <(sed -n '/^inner() {/,/^}/p' "$REPO/tools/module-smoke.sh")
	phase_wanted() { [ "$1" = 0 ]; }
	gdbus() { echo '(true,)'; }
	sleep() { :; }
	kill() { :; }
	inner
)

: >"$ENUM_LOG/backend.log"
expect_accepted "module enumeration accepts p11tool's empty-result status" \
	module_phase_zero
P11_STATUS=0
P11_OUTPUT=""
expect_accepted "module enumeration accepts successful empty consumers" \
	module_phase_zero
for P11_STATUS in 1 2 124 137; do
	expect_refused "module enumeration rejects p11tool failure $P11_STATUS" \
		module_phase_zero
done
P11_STATUS=2
P11_OUTPUT="No matching objects found"
for PKCS11_STATUS in 1 124 137; do
	expect_refused "module enumeration rejects pkcs11-tool failure $PKCS11_STATUS" \
		module_phase_zero
done
PKCS11_STATUS=0
SHOW_CHOOSER=1
expect_refused "module enumeration rejects a chooser without a grant" \
	module_phase_zero
SHOW_CHOOSER=0
P11_STATUS=0
P11_OUTPUT="Object 0:"
expect_refused "module enumeration rejects p11tool objects" \
	module_phase_zero
P11_OUTPUT=""
PKCS11_OUTPUT="Certificate Object; type = X.509 cert"
expect_refused "module enumeration rejects pkcs11-tool objects" \
	module_phase_zero
rm "$ENUM_LOG/backend.log"
expect_refused "module enumeration requires a backend log" \
	module_phase_zero
unset -f timeout

echo "1..$checks"
[ "$failures" -eq 0 ] || exit 1
