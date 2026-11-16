#!/bin/sh

xcb_routing_digest() (
	[ "$#" -eq 2 ] && xcb_private_directory "$1" && xcb_private_directory "$2" || exit 1
	{
		for name in network.source firewall.source openvpn.source dhcp.source live leases.raw profile.source sources lan_networks lan_subnets; do
			xcb_private_file "$1/$name" || exit 1
			sha256sum < "$1/$name" || exit 1
		done
		if [ -e "$1/credentials.sha256" ]; then
			xcb_private_file "$1/credentials.sha256" && sha256sum < "$1/credentials.sha256" || exit 1
		fi
		for name in pbr.source destinations dns; do
			xcb_private_file "$2/$name" && sha256sum < "$2/$name" || exit 1
		done
		for directory in "$1/resources" "$2/resources"; do
			for resource in "$directory/"*; do
				[ -e "$resource" ] || continue
				xcb_private_file "$resource" || exit 1
				printf '%s\n' "${resource##*/}"
				sha256sum < "$resource" || exit 1
			done
		done
		xcb_config_file "$XCB_CONFIG_DIR/xcloud-bypass" && xcb_uci_clean xcloud-bypass || exit 1
		sha256sum < "$XCB_CONFIG_DIR/xcloud-bypass" || exit 1
	} > "$2/review.input" || exit 1
	sha256sum < "$2/review.input" | cut -d ' ' -f 1
)

xcb_routing_leases() (
	[ "$#" -eq 0 ] || exit 1
	umask 077
	runtime=$(xcb_runtime_directory) && work=$(mktemp -d "$runtime/leases.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	if [ -e "$XCB_LEASE_FILE" ] || [ -L "$XCB_LEASE_FILE" ]; then
		xcb_config_file "$XCB_LEASE_FILE" && [ "$(wc -c < "$XCB_LEASE_FILE")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
	fi
	xcb_discover_leases "$work" > "$work/leases" || exit 1
	xcb_config_file "$XCB_CONFIG_DIR/dhcp" && xcb_uci_clean dhcp || exit 1
	xcb_uci_export "$XCB_CONFIG_DIR/dhcp" > "$work/dhcp.export" || exit 1
	awk -v package=dhcp -f "$XCB_LIBRARY_DIR/uci-inspect.awk" "$work/dhcp.export" > "$work/dhcp.table" || exit 1
	awk -F '\t' '$1=="S" { host[$2]=($3=="host") }
		$1=="V" { v[$2,$3]=$4 }
		END { for(s in host) if(host[s]) print v[s,"ip"] "\t" v[s,"name"] }' "$work/dhcp.table" >> "$work/leases" || exit 1
	tab=$(printf '\t')
	while IFS="$tab" read -r address name; do
		xcb_valid_ipv4 "$address" && xcb_valid_hostname "$name" || continue
		printf '%s\t%s\n' "$address" "$name"
	done < "$work/leases" | LC_ALL=C sort -u | head -n 64
)

xcb_routing_preview() (
	[ "$#" -eq 8 ] || exit 1
	network='' policy=''
	trap '[ -z "$network" ] || xcb_network_discard "$network"; [ -z "$policy" ] || xcb_policy_discard "$policy"' EXIT
	trap 'exit 1' HUP INT TERM
	if ! network=$(xcb_network_prepare "$1" "$2" "$3" "$4"); then
		json_add_boolean ok 0
		json_add_string code vpn_scope
		json_dump
		exit 0
	fi
	if ! policy=$(xcb_policy_prepare "$network" "$5" "$6" "$7" "$8"); then
		json_add_boolean ok 0
		json_add_string code dns_policy
		json_dump
		exit 0
	fi
	for name in scope sources lan_networks lan_subnets interface; do
		xcb_private_file "$network/$name" && [ "$(wc -c < "$network/$name")" -le "$XCB_MAX_LIST_BYTES" ] || exit 1
		value=$(cat "$network/$name") || exit 1
		json_add_string "$name" "$value"
	done
	for name in dns destinations; do
		xcb_private_file "$policy/$name" && [ "$(wc -c < "$policy/$name")" -le "$XCB_MAX_LIST_BYTES" ] || exit 1
		value=$(cat "$policy/$name") || exit 1
		json_add_string "$name" "$value"
	done
	value=$(xcb_routing_digest "$network" "$policy") || exit 1
	json_add_string review "$value"
	value=$(while IFS= read -r warning; do
		case "$warning" in
			client_dns_must_use_router|encrypted_dns_and_cached_answers_may_bypass_sets|static_console_addresses_may_be_outdated|ipv4_only_authentication_policies|shared_pbr_will_be_enabled|shared_pbr_resolver_will_change) printf '%s\n' "$warning" ;;
			possible_policy_overlap:*) printf '%s\n' possible_policy_overlap ;;
		esac
	done < "$policy/warnings" | sort -u) || exit 1
	json_add_string warnings "$value"
	json_add_boolean ok 1
	json_dump
)
