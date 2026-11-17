#!/bin/sh

svpn_ip() {
	"$SVPN_IP" "$@"
}

svpn_valid_netdev() (
	[ "$#" -eq 1 ] || exit 1
	case "$1" in ''|-*|*[!a-zA-Z0-9_.-]*) exit 1 ;; esac
	[ "${#1}" -le 15 ]
)

svpn_json_field() {
	jsonfilter -i "$1" -e "$2" 2>/dev/null
}

# collect active addresses, not remembered or inactive netifd values
svpn_discover_live() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	work=$1
	ubus -t 5 call network.interface dump > "$work/live.json" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/live.json")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
	names=$(svpn_json_field "$work/live.json" '@.interface[*].interface') || exit 1
	[ -n "$names" ] || exit 1
	set -f
	index=0
	for name in $names; do
		[ "$index" -lt 128 ] && svpn_valid_interface "$name" || exit 1
		base="@.interface[$index]"
		[ "$(svpn_json_field "$work/live.json" "$base.interface")" = "$name" ] || exit 1
		up=$(svpn_json_field "$work/live.json" "$base.up") || exit 1
		case "$up" in true|false) ;; *) exit 1 ;; esac
		device=$(svpn_json_field "$work/live.json" "$base.l3_device" || :)
		zone=$(svpn_json_field "$work/live.json" "$base.data.zone" || :)
		[ -z "$device" ] || svpn_valid_netdev "$device" || exit 1
		[ -z "$zone" ] || svpn_valid_identifier "$zone" || exit 1
		printf 'I\t%s\t%s\t%s\t%s\n' "$name" "$up" "${device:--}" "${zone:--}"
		if [ "$up" = true ]; then
			addresses=$(svpn_json_field "$work/live.json" "$base['ipv4-address'][*].address" || :)
			address_index=0
			for address in $addresses; do
				[ "$address_index" -lt 32 ] && svpn_valid_ipv4 "$address" || exit 1
				[ "$(svpn_json_field "$work/live.json" "$base['ipv4-address'][$address_index].address")" = "$address" ] || exit 1
				mask=$(svpn_json_field "$work/live.json" "$base['ipv4-address'][$address_index].mask") || exit 1
				svpn_valid_uint "$mask" 32 || exit 1
				printf 'A\t%s\t%s\t%s\n' "$name" "$address" "$mask"
				address_index=$((address_index + 1))
			done
		fi
		index=$((index + 1))
	done
)

svpn_discover_configs() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	for package in network firewall openvpn dhcp; do
		svpn_config_file "$SVPN_CONFIG_DIR/$package" && svpn_uci_clean "$package" || exit 1
		cp -- "$SVPN_CONFIG_DIR/$package" "$1/$package.source" || exit 1
		chmod 600 "$1/$package.source" || exit 1
		svpn_uci_export "$1/$package.source" > "$1/$package.export" || exit 1
		awk -v package="$package" -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" \
			"$1/$package.export" > "$1/$package.table" || exit 1
	done
)

svpn_discover_leases() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	# unsupported resolver layouts are checked before activation
	if [ ! -e "$SVPN_LEASE_FILE" ] && [ ! -L "$SVPN_LEASE_FILE" ]; then exit 0; fi
	svpn_config_file "$SVPN_LEASE_FILE" || exit 1
	now=$(date +%s) || exit 1
	case "$now" in ''|*[!0-9]*) exit 1 ;; esac
	[ "${#now}" -le 12 ] || exit 1
	awk -v now="$now" '
		NF == 5 && $1 ~ /^[0-9]+$/ && ($1 == 0 || $1 > now) && $4 != "*" {
			if (++count > 4096) exit 1
			print $3 "\t" tolower($4)
		}
	' "$SVPN_LEASE_FILE"
)

# OpenVPN clients the user configured outside this app
svpn_discover_clients() (
	[ "$#" -eq 0 ] || exit 1
	svpn_config_file "$SVPN_CONFIG_DIR/openvpn" && svpn_uci_clean openvpn || exit 1
	runtime=$(svpn_runtime_directory) || exit 1
	work=$(mktemp -d "$runtime/clients.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	cp "$SVPN_CONFIG_DIR/openvpn" "$work/openvpn" && chmod 600 "$work/openvpn" || exit 1
	svpn_uci_export "$work/openvpn" > "$work/export" || exit 1
	awk -v package=openvpn -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/export" > "$work/table" || exit 1
	awk -F '\t' '$1 == "S" && $3 == "openvpn" && $4 != "-" && $4 !~ /^svpn_/ { print $4 }' "$work/table"
)
