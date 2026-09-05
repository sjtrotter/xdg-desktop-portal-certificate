#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
#
# test-tools-lib.sh -- the two parts of tools/lib.sh that decide something
# dangerous: which portals.conf the development stack ends up with, and which
# directories it is willing to delete.
#
# WHY THESE ARE TESTED IN SHELL. Both are shell, both were wrong, and both fail
# in ways nobody sees: a portals.conf that quietly drops a `none` gives a
# development stack a backend the session had switched OFF, and a fixture check
# that accepts a forged marker gives `rm -rf` a directory this project did not
# make. Neither shows up in a run that works.
#
# Everything here runs inside one mktemp -d and touches nothing else.

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

# A subshell that must die. tools/lib.sh calls exit 40 on refusal.
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

# THE FIXTURE HELPERS ARE TESTED AGAINST A TMPDIR OF THEIR OWN, so that nothing
# here can reach the operator's real scratch directories.
export TMPDIR="$ROOT/tmp"
mkdir -p "$TMPDIR"

# shellcheck source=tools/lib.sh
. "$REPO/tools/lib.sh"

echo "TAP version 13"

# ------------------------------------------------------------ the portal chain

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
org.freedesktop.impl.portal.experimental.Certificate=somethingelse;
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

# THE ONE THE REVIEW ASKED FOR. A user configuration that switches Screenshot
# off must survive being merged with an /etc file that switches it on: the
# frontend consults the user's first and stops there.
expect_line "a user 'none' beats a later backend for the same interface" \
	"$FLAT" "org.freedesktop.impl.portal.Screenshot=none;"

# An interface only /etc names still resolves, and picks up /etc's default
# behind its own list, which is the order the frontend tries them in.
expect_line "an interface named only in /etc keeps its list and then the default" \
	"$FLAT" "org.freedesktop.impl.portal.Access=gtk;gnome;"

expect_line "the default carries through" "$FLAT" "default=gnome;"

# ---------------------------------------------------- the generated portal dir

mkdir -p "$ROOT/data-home/xdg-desktop-portal/portals"
DEVDIR="$ROOT/devdir"
mkdir -p "$DEVDIR"

xdp_write_portal_dir "$DEVDIR" "$REPO" private 2>/dev/null

expect_line "the Certificate line names this backend" \
	"$DEVDIR/portals.conf" "org.freedesktop.impl.portal.experimental.Certificate=certificate;"

expect_no_line "the configured Certificate backend is replaced, not shadowed" \
	"$DEVDIR/portals.conf" "Certificate=somethingelse"

expect_line "a private run switches the Secret backend off" \
	"$DEVDIR/portals.conf" "org.freedesktop.impl.portal.Secret=none;"

expect_line "the user's Screenshot=none survives into the generated file" \
	"$DEVDIR/portals.conf" "org.freedesktop.impl.portal.Screenshot=none;"

rm -f "$DEVDIR/portals.conf"
xdp_write_portal_dir "$DEVDIR" "$REPO" live 2>/dev/null

expect_no_line "a live run leaves the Secret backend alone" \
	"$DEVDIR/portals.conf" "^org.freedesktop.impl.portal.Secret="

# -------------------------------------------------------- the fixture checks

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
expect_refused "a fixture that is not 0700 is refused rather than repaired" \
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
expect_eq "and it is gone" "gone" "$([ -e "$GOOD" ] && echo present || echo gone)"

expect_refused "fixture_remove refuses a directory it did not make" \
	fixture_remove "$UNMARKED" libtest

echo "1..$checks"
[ "$failures" -eq 0 ] || exit 1
