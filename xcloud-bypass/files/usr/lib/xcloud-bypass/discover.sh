#!/bin/sh

xcb_ip() {
	"$XCB_IP" "$@"
}

xcb_valid_netdev() (
	[ "$#" -eq 1 ] || exit 1
	case "$1" in ''|-*|*[!a-zA-Z0-9_.-]*) exit 1 ;; esac
	[ "${#1}" -le 15 ]
)

xcb_json_field() {
	jsonfilter -i "$1" -e "$2" 2>/dev/null
}

# collect active addresses, not remembered or inactive netifd values
xcb_discover_live() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	work=$1
	ubus -t 5 call network.interface dump > "$work/live.json" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/live.json")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
	names=$(xcb_json_field "$work/live.json" '@.interface[*].interface') || exit 1
	[ -n "$names" ] || exit 1
	set -f
	index=0
	for name in $names; do
		[ "$index" -lt 128 ] && xcb_valid_interface "$name" || exit 1
		base="@.interface[$index]"
		[ "$(xcb_json_field "$work/live.json" "$base.interface")" = "$name" ] || exit 1
		up=$(xcb_json_field "$work/live.json" "$base.up") || exit 1
		case "$up" in true|false) ;; *) exit 1 ;; esac
		device=$(xcb_json_field "$work/live.json" "$base.l3_device" || :)
		zone=$(xcb_json_field "$work/live.json" "$base.data.zone" || :)
		[ -z "$device" ] || xcb_valid_netdev "$device" || exit 1
		[ -z "$zone" ] || xcb_valid_identifier "$zone" || exit 1
		printf 'I\t%s\t%s\t%s\t%s\n' "$name" "$up" "${device:--}" "${zone:--}"
		if [ "$up" = true ]; then
			addresses=$(xcb_json_field "$work/live.json" "$base['ipv4-address'][*].address" || :)
			address_index=0
			for address in $addresses; do
				[ "$address_index" -lt 32 ] && xcb_valid_ipv4 "$address" || exit 1
				[ "$(xcb_json_field "$work/live.json" "$base['ipv4-address'][$address_index].address")" = "$address" ] || exit 1
				mask=$(xcb_json_field "$work/live.json" "$base['ipv4-address'][$address_index].mask") || exit 1
				xcb_valid_uint "$mask" 32 || exit 1
				printf 'A\t%s\t%s\t%s\n' "$name" "$address" "$mask"
				address_index=$((address_index + 1))
			done
		fi
		index=$((index + 1))
	done
)

xcb_discover_configs() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	for package in network firewall openvpn dhcp; do
		xcb_config_file "$XCB_CONFIG_DIR/$package" && xcb_uci_clean "$package" || exit 1
		cp -- "$XCB_CONFIG_DIR/$package" "$1/$package.source" || exit 1
		chmod 600 "$1/$package.source" || exit 1
		xcb_uci_export "$1/$package.source" > "$1/$package.export" || exit 1
		awk -v package="$package" -f "$XCB_LIBRARY_DIR/uci-inspect.awk" \
			"$1/$package.export" > "$1/$package.table" || exit 1
	done
)

xcb_discover_leases() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	# unsupported resolver layouts are checked before activation
	if [ ! -e "$XCB_LEASE_FILE" ] && [ ! -L "$XCB_LEASE_FILE" ]; then exit 0; fi
	xcb_config_file "$XCB_LEASE_FILE" || exit 1
	now=$(date +%s) || exit 1
	case "$now" in ''|*[!0-9]*) exit 1 ;; esac
	[ "${#now}" -le 12 ] || exit 1
	awk -v now="$now" '
		NF == 5 && $1 ~ /^[0-9]+$/ && ($1 == 0 || $1 > now) && $4 != "*" {
			if (++count > 4096) exit 1
			print $3 "\t" tolower($4)
		}
	' "$XCB_LEASE_FILE"
)
