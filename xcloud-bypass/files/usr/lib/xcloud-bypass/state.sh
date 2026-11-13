#!/bin/sh

xcb_state_error() {
	printf '%s\n' "$1" >&2
	return 1
}

xcb_runtime_directory() (
	# resolve only the fixed system prefix, never an uploaded path
	prefix=$(CDPATH='' cd -- "${XCB_RUNTIME_DIR%/*}" && pwd -P) || exit 1
	xcb_make_private_directory "$prefix/${XCB_RUNTIME_DIR##*/}" || exit 1
	printf '%s\n' "$prefix/${XCB_RUNTIME_DIR##*/}"
)

xcb_state_id() {
	[ "$#" -eq 1 ] || return 1
	case "$1" in ''|*[!a-f0-9]*) return 1 ;; esac
	[ "${#1}" -eq 32 ]
}

xcb_state_read() (
	[ "$#" -eq 1 ] && xcb_private_file "$1" || exit 1
	[ "$(wc -c < "$1")" -le 256 ] || exit 1
	cat -- "$1"
)

xcb_state_put() (
	[ "$#" -ge 1 ] && [ "$#" -le 2 ] || exit 1
	case "${2:-}" in ''|sync) ;; *) exit 1 ;; esac
	xcb_private_directory "${1%/*}" || exit 1
	if [ -e "$1" ] || [ -L "$1" ]; then xcb_private_file "$1" || exit 1; fi
	umask 077
	stage=$(mktemp "${1%/*}/.write.XXXXXXXX") || exit 1
	trap 'rm -f -- "$stage"' EXIT
	trap 'exit 1' HUP INT TERM
	head -c "$((XCB_MAX_SNAPSHOT_BYTES + 9))" > "$stage" || exit 1
	[ "$(wc -c < "$stage")" -le "$((XCB_MAX_SNAPSHOT_BYTES + 8))" ] || exit 1
	xcb_private_file "$stage" || exit 1
	if [ "${2:-}" = sync ]; then sync || exit 1; fi
	mv -f -- "$stage" "$1" || exit 1
)

xcb_state_mark() {
	printf '%s\n' "$2" | xcb_state_put "$1" "${3:-}"
}

xcb_state_budget() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	# include metadata and temporary work, not just profile payloads
	bytes=$(du -sk -- "$1") || exit 1
	set -- $bytes
	[ "$1" -le "$((XCB_MAX_STATE_BYTES / 1024))" ]
)

xcb_uptime() {
	awk '{ split($1, seconds, "."); print seconds[1]; exit }' /proc/uptime
}

xcb_boot_id() {
	cat /proc/sys/kernel/random/boot_id
}

xcb_resource_target() (
	[ "$#" -eq 2 ] || exit 1
	case "$1" in
		file)
			case "$2" in
				profile.*/*)
					bundle=${2%/*}
					case "$bundle" in profile.?*) ;; *) exit 1 ;; esac
					case "${bundle#profile.}" in *[!a-zA-Z0-9]*) exit 1 ;; esac
					[ "${#bundle}" -le 32 ] || exit 1
					case "${2##*/}" in client.ovpn|credentials|summary) ;; *) exit 1 ;; esac ;;
				*) exit 1 ;;
			esac ;;
		option|section)
			IFS=.
			set -f
			kind=$1
			set -- $2
			case "$1" in xcloud-bypass|network|firewall|openvpn|pbr|dhcp) ;; *) exit 1 ;; esac
			xcb_valid_identifier "${2:-}" || exit 1
			if [ "$kind" = section ]; then
				[ "$#" -eq 2 ] && xcb_reserved_identifier "$2" || exit 1
			else
				[ "$#" -eq 3 ] && xcb_valid_identifier "$3" || exit 1
				# whole owned sections and shared options cannot overlap
				! xcb_reserved_identifier "$2" || exit 1
			fi ;;
		*) exit 1 ;;
	esac
)

xcb_config_file() (
	[ "$#" -eq 1 ] || exit 1
	xcb_check_directory_chain "${1%/*}" || exit 1
	[ -f "$1" ] && [ ! -L "$1" ] || exit 1
	info=$(stat -c '%u %a %h %s' "$1") || exit 1
	set -- $info
	[ "$1" = "$(id -u)" ] && [ "$3" = 1 ] || exit 1
	[ "$((0$2 & 0022))" -eq 0 ] && [ "$4" -le "$XCB_MAX_SNAPSHOT_BYTES" ]
)

xcb_uci_clean() (
	if [ -e "$XCB_CONFIG_OVERRIDE_DIR/$1" ] || [ -L "$XCB_CONFIG_OVERRIDE_DIR/$1" ]; then
		xcb_state_error 'A UCI override is active. Resolve it before continuing.'; exit 1
	fi
	changes=$(uci -q changes "$1" 2>/dev/null) || exit 1
	[ -z "$changes" ] || xcb_state_error 'Commit or discard pending UCI edits before continuing.'
)

xcb_uci_export() (
	# an absolute filename bypasses UCI's shared delta directories
	uci -q -N export "$1" 2>/dev/null
)

xcb_uci_record() (
	target=$1
	mode=$2
	input=$3
	replacement=${4:-/dev/null}
	IFS=.
	set -f
	set -- $target
	awk -v section="$2" -v option="${3:-}" -v mode="$mode" \
		-v replacement="$replacement" -f "$XCB_LIBRARY_DIR/uci-record.awk" "$input"
)

xcb_resource_read() (
	[ "$#" -eq 4 ] && xcb_resource_target "$1" "$2" || exit 1
	kind=$1 target=$2 output=$3 work=$4
	if [ "$kind" = file ]; then
		path=$XCB_PROFILE_DIR/$target
		xcb_private_directory "${path%/*}" || exit 1
		if [ ! -e "$path" ] && [ ! -L "$path" ]; then
			printf 'missing\n' > "$output"
		else
			xcb_private_file "$path" || exit 1
			[ "$(wc -c < "$path")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
			{ printf 'present\n'; cat -- "$path"; } > "$output" || exit 1
		fi
	else
		package=${target%%.*}
		xcb_config_file "$XCB_CONFIG_DIR/$package" && xcb_uci_clean "$package" || exit 1
		cp -- "$XCB_CONFIG_DIR/$package" "$work/source" && chmod 600 "$work/source" || exit 1
		xcb_uci_export "$work/source" > "$work/export" || exit 1
		xcb_uci_record "$target" read "$work/export" > "$work/fragment" || exit 1
		if [ -s "$work/fragment" ]; then
			{ printf 'present\n'; cat "$work/fragment"; } > "$output" || exit 1
		else
			printf 'missing\n' > "$output"
		fi
	fi
)

xcb_resource_write() (
	[ "$#" -eq 5 ] && xcb_resource_target "$1" "$2" || exit 1
	kind=$1 target=$2 desired=$3 expected=$4 work=$5
	xcb_resource_read "$kind" "$target" "$work/current" "$work" || exit 1
	cmp -s "$expected" "$work/current" || exit 1
	status=$(head -n 1 "$desired") || exit 1
	case "$status" in present|missing) ;; *) exit 1 ;; esac
	tail -n +2 "$desired" > "$work/value" || exit 1
	if [ "$kind" = file ]; then
		path=$XCB_PROFILE_DIR/$target
		if [ "$status" = missing ]; then
			rm -f -- "$path"
		else
			xcb_state_put "$path" sync < "$work/value"
		fi
	else
		package=${target%%.*}
		path=$XCB_CONFIG_DIR/$package
		mode=$(stat -c '%a' "$path") || exit 1
		# retain a copy for detecting edits made while the candidate is built
		cp -- "$work/source" "$work/compare" || exit 1
		xcb_uci_record "$target" replace "$work/export" "$work/value" > "$work/candidate" || exit 1
		xcb_uci_export "$work/candidate" > "$work/checked" || exit 1
		xcb_uci_record "$target" read "$work/checked" > "$work/result" || exit 1
		cmp -s "$work/value" "$work/result" || exit 1
		xcb_uci_clean "$package" && xcb_config_file "$path" || exit 1
		cmp -s "$path" "$work/compare" || exit 1
		stage=$(mktemp "$XCB_CONFIG_DIR/.xcloud.XXXXXXXX") || exit 1
		trap 'rm -f -- "$stage"' EXIT
		trap 'exit 1' HUP INT TERM
		cat "$work/candidate" > "$stage" && chmod "$mode" "$stage" || exit 1
		sync || exit 1
		cmp -s "$path" "$work/compare" || exit 1
		mv -f -- "$stage" "$path"
	fi
)

xcb_resource_validate() (
	[ "$#" -eq 4 ] && xcb_resource_target "$1" "$2" || exit 1
	kind=$1 target=$2 snapshot=$3 work=$4
	case "$(head -n 1 "$snapshot")" in
		missing) [ "$(wc -c < "$snapshot")" -eq 8 ]; exit ;;
		present) ;;
		*) exit 1 ;;
	esac
	[ "$kind" != file ] || exit 0
	tail -n +2 "$snapshot" > "$work/value" || exit 1
	[ -s "$work/value" ] || exit 1
	section=${target#*.}
	section=${section%%.*}
	: > "$work/skeleton"
	if [ "$kind" = option ]; then printf "config settings '%s'\n" "$section" > "$work/skeleton"; fi
	{ cat "$work/skeleton"; cat "$work/value"; } > "$work/candidate" || exit 1
	xcb_uci_export "$work/candidate" > "$work/checked" || exit 1
	xcb_uci_record "$target" read "$work/checked" > "$work/result" || exit 1
	cmp -s "$work/value" "$work/result" || exit 1
	xcb_uci_record "$target" replace "$work/checked" /dev/null > "$work/remainder" || exit 1
	cmp -s "$work/skeleton" "$work/remainder"
)
