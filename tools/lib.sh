#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
# Sourced helpers for validated fixture directories and development portal configuration.

# Validate fixture paths and markers before loading modules or deleting data; see docs/TESTING.md.

XDP_FIXTURE_MARKER=".xdg-desktop-portal-certificate-fixture"

lib_die() {
	echo "${0##*/}: $*" >&2
	exit 40
}

fixture_tmp_root() {
	local root="${TMPDIR:-/tmp}"

	root="$(realpath -m -- "$root")" || lib_die "TMPDIR '$root' could not be resolved"
	printf '%s' "${root%/}"
}

fixture_no_symlinks() {
	local path="$1" lexical real

	lexical="$(realpath -m -s -- "$path")" || return 1
	real="$(realpath -e -- "$path" 2>/dev/null)" || return 1
	[ "$lexical" = "$real" ]
}

fixture_under_tmp() {
	local path real root

	path="$1"
	root="$(fixture_tmp_root)"
	real="$(realpath -m -- "$path")" || return 1

	case "$real" in
	"$root"/?*) return 0 ;;
	*) return 1 ;;
	esac
}

# Ancestors must be owned by this user or root and writable by others only when sticky.
fixture_dir_safe() {
	local path="$1" owner mode sticky group other

	owner="$(stat -c %u -- "$path" 2>/dev/null)" || return 1
	[ "$owner" = "$(id -u)" ] || [ "$owner" = 0 ] || return 1

	mode="$(stat -c %04a -- "$path" 2>/dev/null)" || return 1
	sticky=$((0${mode:0:1} & 1))
	group=$((0${mode:2:1} & 2))
	other=$((0${mode:3:1} & 2))

	if [ "$group" -ne 0 ] || [ "$other" -ne 0 ]; then
		[ "$sticky" -eq 1 ] || return 1
	fi

	return 0
}

fixture_ancestors_ok() {
	local real="$1" root path

	root="$(fixture_tmp_root)"
	fixture_dir_safe "$root" ||
		lib_die "Fixture root $root has unsafe ownership or permissions"

	path="$(dirname -- "$real")"
	while [ "$path" != "$root" ] && [ "$path" != "/" ]; do
		fixture_dir_safe "$path" ||
			lib_die "Fixture ancestor $path has unsafe ownership or permissions"
		path="$(dirname -- "$path")"
	done
}

# Write a marker only in a directory this script just created.
fixture_claim() {
	local dir="$1" tag="$2"

	(umask 177 && printf '%s\n' "$tag" >"$dir/$XDP_FIXTURE_MARKER") ||
		lib_die "Fixture marker could not be written in $dir"
	chmod 600 "$dir/$XDP_FIXTURE_MARKER" || lib_die "Fixture marker permissions could not be set in $dir"
}

fixture_refuse() {
	lib_die "$2
Fixture cannot be used or removed automatically. Remove it manually if disposable:
    rm -rf -- '$1'"
}

fixture_check() {
	local dir="$1" tag="$2" real marker owner mode claimed kind

	[ -L "$dir" ] && lib_die "$dir is a symlink; refusing to use it"
	[ -d "$dir" ] || lib_die "$dir exists and is not a directory"

	fixture_no_symlinks "$dir" ||
		lib_die "$dir is reached through a symlink; refusing to use it"

	fixture_under_tmp "$dir" ||
		lib_die "Fixture $dir must be inside ${TMPDIR:-/tmp}; set TMPDIR to use another location"

	real="$(realpath -e -- "$dir")" || lib_die "Fixture path $dir could not be resolved"
	fixture_ancestors_ok "$real"

	owner="$(stat -c %u -- "$real")"
	[ "$owner" = "$(id -u)" ] ||
		fixture_refuse "$real" "Fixture $real must be owned by uid $(id -u); owner is $owner."

	marker="$real/$XDP_FIXTURE_MARKER"

	[ -L "$marker" ] &&
		fixture_refuse "$real" "$real has a symlink where its fixture marker should be."
	kind="$(stat -c %F -- "$marker" 2>/dev/null)" || kind=""
	[ "$kind" = "regular file" ] ||
		fixture_refuse "$real" "Fixture $real has no regular $XDP_FIXTURE_MARKER file."

	owner="$(stat -c %u -- "$marker")"
	[ "$owner" = "$(id -u)" ] ||
		fixture_refuse "$real" "Fixture marker in $real has owner uid $owner."

	mode="$(stat -c %a -- "$marker")"
	[ "$mode" = "600" ] ||
		fixture_refuse "$real" "Fixture marker in $real has mode $mode; mode 600 is required.
Re-create the fixture or set marker permissions:
    chmod 600 -- '$marker'"

	claimed="$(cat -- "$marker" 2>/dev/null)"
	[ "$claimed" = "$tag" ] ||
		fixture_refuse "$real" "Fixture $real has tag '$claimed'; expected '$tag'."

	mode="$(stat -c %a -- "$real")"
	case "$mode" in
	700 | 500) ;;
	*)
		fixture_refuse "$real" "Fixture $real has mode $mode; mode 700 or 500 is required.
An exposed directory may contain a forged marker; re-create the fixture."
		;;
	esac
}

# Exclusive creation with umask 077 prevents adoption or brief exposure of another directory.
fixture_create() {
	local dir="$1" tag="$2"

	fixture_under_tmp "$dir" ||
		lib_die "$dir is not under ${TMPDIR:-/tmp}; refusing to create a fixture there"

	(umask 077 && mkdir -- "$dir") || lib_die "Fixture directory $dir could not be created"
	fixture_claim "$dir" "$tag"
}

fixture_make() {
	local dir="$1" tag="$2"

	[ -e "$dir" ] || [ -L "$dir" ] || fixture_create "$dir" "$tag"
	fixture_check "$dir" "$tag"
}

# Delete only a checked resolved path without crossing filesystem boundaries.
fixture_remove() {
	local dir="$1" tag="$2" real

	[ -e "$dir" ] || [ -L "$dir" ] || return 0
	fixture_check "$dir" "$tag"

	real="$(realpath -e -- "$dir")" || lib_die "Fixture path $dir could not be resolved"
	rm -rf --one-file-system -- "$real" || lib_die "Fixture directory $real could not be removed"
}

fixture_mktemp() {
	local prefix="$1" tag="$2" dir

	dir="$(mktemp -d "${TMPDIR:-/tmp}/$prefix.XXXXXXXX")" || lib_die "mktemp failed"
	fixture_claim "$dir" "$tag"
	printf '%s' "$dir"
}

xdp_data_dirs() {
	local dirs

	printf '%s\n' "${XDG_DATA_HOME:-$HOME/.local/share}"
	dirs="${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
	printf '%s\n' "$dirs" | tr ':' '\n'
}

xdp_desktops() {
	printf '%s\n' "${XDG_CURRENT_DESKTOP:-}" | tr ':' '\n' | tr '[:upper:]' '[:lower:]' |
		grep -v '^$'
}

# Within each directory, desktop-specific configuration precedes portals.conf.
xdp_config_chain() {
	local dir desktop found

	for dir in "${XDG_CONFIG_HOME:-$HOME/.config}/xdg-desktop-portal" \
		$(printf '%s\n' "${XDG_CONFIG_DIRS:-/etc/xdg}" | tr ':' '\n' | sed 's:$:/xdg-desktop-portal:') \
		/etc/xdg-desktop-portal \
		$(xdp_data_dirs | sed 's:$:/xdg-desktop-portal:') \
		/usr/share/xdg-desktop-portal; do
		found=""

		while read -r desktop; do
			if [ -f "$dir/$desktop-portals.conf" ]; then
				found="$dir/$desktop-portals.conf"
				break
			fi
		done < <(xdp_desktops)

		[ -z "$found" ] && [ -f "$dir/portals.conf" ] && found="$dir/portals.conf"
		[ -n "$found" ] && printf '%s\n' "$found"
	done | awk '!seen[$0]++'
}

# Resolve interfaces across the configuration chain, preserving interface/default fallback order and stopping at none; see docs/TESTING.md.
xdp_flatten_preferred() {
	[ $# -gt 0 ] || return 0

	awk '
	function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
	function has_none(s,   n, a, i) {
		n = split(s, a, ";")
		for (i = 1; i <= n; i++) if (trim(a[i]) == "none") return 1
		return 0
	}
	function add(item) {
		if (item == "" || item == "none" || (item in used)) return
		used[item] = 1
		out = (out == "" ? item : out ";" item)
	}
	function addlist(s,   n, a, i) {
		n = split(s, a, ";")
		for (i = 1; i <= n; i++) add(trim(a[i]))
	}
	function terminate() { out = (out == "" ? "none" : out ";none"); return out }
	function flatten(key,   i, il, dl) {
		delete used
		out = ""
		for (i = 1; i <= nf; i++) {
			il = ((i SUBSEP key) in vals) ? vals[i, key] : NOKEY
			dl = ((i SUBSEP "default") in vals) ? vals[i, "default"] : NOKEY
			if (il != NOKEY) {
				if (has_none(il)) return terminate()
				addlist(il)
				if (dl != NOKEY) addlist(dl)
			} else if (dl != NOKEY) {
				if (has_none(dl)) return terminate()
				addlist(dl)
			}
		}
		return out
	}
	BEGIN { NOKEY = "\001none-such\001"; nf = 0; nk = 0 }
	FNR == 1 { nf++; section = "" }
	{
		line = trim($0)
		if (line ~ /^[#;]/ || line == "") next
		if (line ~ /^\[.*\]$/) { section = substr(line, 2, length(line) - 2); next }
		if (section != "preferred") next
		eq = index(line, "=")
		if (eq == 0) next
		key = trim(substr(line, 1, eq - 1))
		if (!(key in seen)) { seen[key] = 1; allkeys[++nk] = key }
		vals[nf, key] = trim(substr(line, eq + 1))
	}
	END {
		print "[preferred]"
		for (i = 1; i <= nk; i++) {
			if (allkeys[i] == "default") continue
			r = flatten(allkeys[i])
			if (r != "") printf "%s=%s;\n", allkeys[i], r
		}
		r = flatten("default")
		if (r != "") printf "default=%s;\n", r
	}
	' "$@"
}

# Replace existing keys because the generated file has one preferred section and the first key wins.
xdp_conf_set() {
	local file="$1" key="$2" value="$3" tmp="$1.tmp"

	awk -v k="$key" 'index($0, k "=") != 1' "$file" >"$tmp" || lib_die "Configuration $file could not be rewritten"
	printf '%s=%s\n' "$key" "$value" >>"$tmp"
	mv -f -- "$tmp" "$file" || lib_die "Configuration $file could not be replaced"
}

# XDG_DESKTOP_PORTAL_DIR replaces both portal and configuration search paths; include the desktop's complete effective configuration.
xdp_write_portal_dir() {
	local dir="$1" repo="$2" mode="${3:-private}" source_dir base found
	local chain=()

	for source_dir in $(xdp_data_dirs | sed 's:$:/xdg-desktop-portal/portals:'); do
		[ -d "$source_dir" ] || continue

		for found in "$source_dir"/*.portal; do
			[ -f "$found" ] || continue
			base="$(basename "$found")"
			# The first portal file found wins.
			[ -e "$dir/$base" ] && continue
			ln -s -- "$found" "$dir/$base"
		done
	done

	# Replace any installed certificate.portal so it cannot shadow the build under test.
	rm -f -- "$dir/certificate.portal"
	sed -e '/^#/d' -e '/^$/d' "$repo/data/certificate.portal.in" >"$dir/certificate.portal"

	mapfile -t chain < <(xdp_config_chain)

	# portals.conf is the fallback for every desktop name.
	if [ "${#chain[@]}" -gt 0 ]; then
		xdp_flatten_preferred "${chain[@]}" >"$dir/portals.conf"
		echo "${0##*/}: portals.conf flattened from ${#chain[@]} file(s)" >&2
		printf '%s: chain %s\n' "${0##*/}" "${chain[@]}" >&2
	else
		printf '[preferred]\ndefault=none;\n' >"$dir/portals.conf"
		echo "${0##*/}: no portals.conf on this machine; default=none" >&2
	fi

	xdp_conf_set "$dir/portals.conf" \
		org.freedesktop.impl.portal.experimental.Certificate1 'certificate;'

	# Disable Secret on a private bus to avoid waiting for activation of an absent keyring.
	if [ "$mode" != live ]; then
		xdp_conf_set "$dir/portals.conf" org.freedesktop.impl.portal.Secret 'none;'
	fi
}

xdp_experimental_portals() {
	local enabled="${XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL:-}" name

	for name in "$@"; do
		case ",$enabled," in
		*,"$name",*) ;;
		*) enabled="${enabled:+$enabled,}$name" ;;
		esac
	done
	printf '%s' "$enabled"
}

# Wait up to 30 seconds for the name, stopping early if its expected owner exits.
xdp_wait_for_name() {
	local name="$1" pid="$2" owned=""

	for _ in $(seq 1 120); do
		owned="$(gdbus call --session --dest org.freedesktop.DBus \
			--object-path /org/freedesktop/DBus \
			--method org.freedesktop.DBus.NameHasOwner "$name" 2>/dev/null)"
		case "$owned" in
		*true*) return 0 ;;
		esac

		kill -0 "$pid" 2>/dev/null || return 1
		sleep 0.25
	done

	return 1
}

# Only the smoke runners opt into backend selection; dev-stack/live helpers keep
# their existing GTK behaviour. BACKEND is always an executable path.
xdp_smoke_select_backend() {
	BACKEND_KIND="${BACKEND_KIND:-gtk}"
	case "$BACKEND_KIND" in
	gtk)
		BACKEND="${BACKEND:-$1}"
		CHOOSER_TITLE="Use a Certificate"
		PIN_TITLE="Unlock Security Token"
		;;
	kde)
		BACKEND="${BACKEND:-$(command -v xdg-desktop-portal-kde || printf '%s' /usr/libexec/xdg-desktop-portal-kde)}"
		CHOOSER_TITLE="Choose Certificate"
		PIN_TITLE="Unlock Security Token"
		;;
	gnome)
		BACKEND="${BACKEND:-$(command -v xdg-desktop-portal-gnome || printf '%s' /usr/libexec/xdg-desktop-portal-gnome)}"
		# AdwWindow titles from certificatedialog.ui / certificatepindialog.ui.
		CHOOSER_TITLE="Choose Certificate"
		PIN_TITLE="Unlock Security Token"
		;;
	*) lib_die "BACKEND_KIND takes gtk (default), kde or gnome" ;;
	esac
	export BACKEND_KIND BACKEND CHOOSER_TITLE PIN_TITLE
}

xdp_smoke_prepare() {
	local logdir="$1" repo="$2" fixture="$3" module

	if [ "$BACKEND_KIND" = gtk ]; then
		xdp_write_portal_dir "$logdir/portals" "$repo" private
		return
	fi

	if [ "$BACKEND_KIND" = gnome ]; then
		xdp_smoke_prepare_gnome "$logdir" "$fixture"
		return
	fi

	module="$(cat "$fixture/module-path")"
	# KConfig string lists and the INI backend each escape backslashes.
	# Reject line breaks so a fixture path cannot introduce another key/group.
	case "$module" in
	*[$'\n\r']*) lib_die "SoftHSM module path contains a line break" ;;
	esac
	module="${module//\\/\\\\}"
	module="${module//,/\\,}"
	module="${module//\\/\\\\}"
	module="${module//$'\t'/\\t}"
	module="${module// /\\s}"
	(umask 077 && mkdir -p "$logdir/kde-config" "$logdir/kde-runtime" "$logdir/kde-cache" "$logdir/kde-data") ||
		lib_die "could not create KDE's private XDG directories"
	chmod 700 "$logdir/kde-runtime"
	# LOGDIR can be reused; do not retain descriptors from a previous GTK run.
	rm -f -- "$logdir/portals/"*.portal "$logdir/portals/"*-portals.conf
	cat >"$logdir/kde-config/xdg-desktop-portal-kderc" <<EOF
[Certificate]
Modules=$module
AllowSoftwareTokens=true
EOF
	cat >"$logdir/portals/kde.portal" <<'EOF'
[portal]
DBusName=org.freedesktop.impl.portal.desktop.kde
Interfaces=org.freedesktop.impl.portal.experimental.Certificate1;
UseIn=portal-certificate-smoke;
EOF
	cat >"$logdir/portals/portals.conf" <<'EOF'
[preferred]
default=none;
org.freedesktop.impl.portal.experimental.Certificate1=kde;
EOF
	# Do not activate installed backends or delegate activation to the real
	# session's systemd. All KDE interfaces/names remain on this private bus.
	cat >"$logdir/bus.conf" <<'EOF'
<busconfig>
  <type>session</type>
  <listen>unix:tmpdir=/tmp</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
    <allow own="*"/>
  </policy>
</busconfig>
EOF
	# Skip DesktopPortal's compositor-specific services on the Xvfb display.
	export XDG_CURRENT_DESKTOP=portal-certificate-smoke
	# Inherited platform themes/plugins can probe portals during QApplication
	# construction. They are unnecessary for these real X11 dialogs.
	unset QT_QPA_PLATFORMTHEME QT_QPA_GENERIC_PLUGINS DBUS_STARTER_ADDRESS DBUS_STARTER_BUS_TYPE
	# Stable English window titles, irrespective of the container's locale.
	export LC_ALL=C LANGUAGE=C
}

# Call only inside dbus-run-session, before the frontend can activate a backend.
xdp_smoke_start_kde_backend() {
	# Only the backend gets the private XDG directories; clients keep theirs so
	# p11-kit still finds the module registration the scripts install.
	env XDG_CONFIG_HOME="$LOGDIR/kde-config" XDG_CONFIG_DIRS="$LOGDIR/kde-config" \
		XDG_RUNTIME_DIR="$LOGDIR/kde-runtime" XDG_CACHE_HOME="$LOGDIR/kde-cache" \
		XDG_DATA_HOME="$LOGDIR/kde-data" \
		QT_QPA_PLATFORM=xcb QT_QUICK_BACKEND=software QT_NO_XDG_DESKTOP_PORTAL=1 \
		"$BACKEND" >"$LOGDIR/backend.log" 2>&1 &
	BE=$!
	# Include early frontend failure/interrupt paths in KDE teardown.
	trap 'kill "$BE" ${FE:+"$FE"} ${PERM:+"$PERM"} ${DRIVER:+"$DRIVER"} ${E2E:+"$E2E"} ${SERVER:+"$SERVER"} 2>/dev/null' EXIT
	xdp_wait_for_name org.freedesktop.impl.portal.desktop.kde "$BE" || {
		echo "${0##*/}: KDE never took its private bus name"
		tail -20 "$LOGDIR/backend.log"
		return 40
	}
}

xdp_smoke_run_session() {
	local bus_args=()
	case "$BACKEND_KIND" in
	kde | gnome) bus_args=(--config-file="$LOGDIR/bus.conf") ;;
	esac
	dbus-run-session "${bus_args[@]}" -- "$@"
}

# GNOME shares KDE's private-bus isolation, with its native keyfile and GTK UI.
xdp_smoke_prepare_gnome() {
	local logdir="$1" fixture="$2" module

	module="$(cat "$fixture/module-path")"
	case "$module" in
	*[$'\n\r']*) lib_die "SoftHSM module path contains a line break" ;;
	esac
	# GLib keyfile string-list escaping (semicolon separator).
	module="${module//\\/\\\\}"
	module="${module//;/\\;}"
	module="${module//$'\t'/\\t}"
	module="${module// /\\s}"
	(umask 077 && mkdir -p "$logdir/gnome-config/xdg-desktop-portal-gnome" \
		"$logdir/gnome-runtime" "$logdir/gnome-cache" "$logdir/gnome-data") ||
		lib_die "could not create GNOME's private XDG directories"
	chmod 700 "$logdir/gnome-runtime"
	rm -f -- "$logdir/portals/"*.portal "$logdir/portals/"*-portals.conf
	cat >"$logdir/gnome-config/xdg-desktop-portal-gnome/certificate.conf" <<EOF
[Certificate]
Modules=$module;
AllowSoftwareTokens=true
PinPrompt=dialog
EOF
	cat >"$logdir/portals/gnome.portal" <<'EOF'
[portal]
DBusName=org.freedesktop.impl.portal.desktop.gnome
Interfaces=org.freedesktop.impl.portal.experimental.Certificate1;
UseIn=portal-certificate-smoke;
EOF
	cat >"$logdir/portals/portals.conf" <<'EOF'
[preferred]
default=none;
org.freedesktop.impl.portal.experimental.Certificate1=gnome;
EOF
	# No includes, service directories or systemd activation on this bus.
	cat >"$logdir/bus.conf" <<'EOF'
<busconfig>
  <type>session</type>
  <listen>unix:tmpdir=/tmp</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
    <allow own="*"/>
  </policy>
</busconfig>
EOF
	unset DBUS_STARTER_ADDRESS DBUS_STARTER_BUS_TYPE
	export XDG_CURRENT_DESKTOP=portal-certificate-smoke LC_ALL=C LANGUAGE=C
}

xdp_smoke_start_gnome_backend() {
	# Only this backend sees the temporary configuration. Client p11-kit module
	# registrations and the real session's configuration remain independent.
	env XDG_CONFIG_HOME="$LOGDIR/gnome-config" XDG_CONFIG_DIRS="$LOGDIR/gnome-config" \
		XDG_RUNTIME_DIR="$LOGDIR/gnome-runtime" XDG_CACHE_HOME="$LOGDIR/gnome-cache" \
		XDG_DATA_HOME="$LOGDIR/gnome-data" XDG_SESSION_TYPE=x11 \
		GDK_BACKEND=x11 GSK_RENDERER=cairo GDK_DISABLE=gl,egl,vulkan \
		GTK_A11Y=none "$BACKEND" --verbose >"$LOGDIR/backend.log" 2>&1 &
	BE=$!
	# SIGHUP lets GNOME drain SDK workers/UI before exiting.
	trap 'kill -HUP "$BE" 2>/dev/null; kill ${PROMPTER:+"$PROMPTER"} ${FE:+"$FE"} ${PERM:+"$PERM"} ${DRIVER:+"$DRIVER"} ${E2E:+"$E2E"} ${SERVER:+"$SERVER"} 2>/dev/null' EXIT
	xdp_wait_for_name org.freedesktop.impl.portal.desktop.gnome "$BE" || {
		echo "${0##*/}: GNOME never took its private bus name"
		tail -40 "$LOGDIR/backend.log"
		return 40
	}
	gdbus introspect --session --dest org.freedesktop.impl.portal.desktop.gnome \
		--object-path /org/freedesktop/portal/desktop >"$LOGDIR/gnome-interfaces.log" 2>&1 || return 40
	grep -q 'interface org.freedesktop.impl.portal.experimental.Certificate1' "$LOGDIR/gnome-interfaces.log" || {
		echo "${0##*/}: GNOME has no Certificate1 (check -Dcertificate=enabled and X11 initialization)"
		tail -40 "$LOGDIR/backend.log"
		return 40
	}
	# Preserve startup diagnostics about unavailable Shell/Mutter services. They
	# must be nonfatal; no fake compositor is installed to mask a dependency.
	grep -Ei 'shell|mutter|warning|error|failed' "$LOGDIR/backend.log" \
		>"$LOGDIR/gnome-startup.log" || true
	if [ -s "$LOGDIR/gnome-startup.log" ]; then
		echo "${0##*/}: GNOME private-bus startup diagnostics:"
		cat "$LOGDIR/gnome-startup.log"
	fi
}
