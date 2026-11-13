#!/bin/sh

# source validation, private storage, recovery, profile and discovery libraries first
xcb_table_get() (
	[ "$#" -eq 3 ] || exit 1
	awk -F '\t' -v name="$2" -v key="$3" '
		$1 == "S" && $4 == name { section = $2; found++ }
		$1 == "V" { values[$2,$3] = $4 }
		END { if (found != 1) exit 1; print values[section,key] }
	' "$1"
)

xcb_vpn_file_device() (
	[ "$#" -eq 1 ] && xcb_config_file "$1" || exit 1
	LC_ALL=C awk -v mode=inventory -f "$XCB_LIBRARY_DIR/profile.awk" "$1"
)

xcb_network_owned() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	if [ ! -e "$XCB_PRIVATE_DIR/confirmed" ] && [ ! -L "$XCB_PRIVATE_DIR/confirmed" ]; then exit 0; fi
	confirmed=$(xcb_tx_pointer confirmed) && xcb_tx_load "$confirmed" || exit 1
	for record in "$tx/manifest"/*; do
		[ -e "$record" ] || continue
		xcb_tx_check_record "$record" || exit 1
		kind=$(xcb_state_read "$record/kind") && target=$(xcb_state_read "$record/target") || exit 1
		case "$kind:$target" in section:network.*|section:firewall.*|section:openvpn.*) ;; *) continue ;; esac
		xcb_resource_read "$kind" "$target" "$1/current" "$1" || exit 1
		cmp -s "$record/applied" "$1/current" || {
			xcb_state_error 'A managed network resource was edited outside the application.'; exit 1;
		}
	done
)

# prepare private candidates; applying them requires the recovery lifecycle
xcb_network_prepare() (
	[ "$#" -eq 4 ] && [ "$(id -u)" -eq 0 ] || exit 1
	mode=$1 selection=$2
	case "$mode" in managed|external) ;; *) exit 1 ;; esac
	networks=$(xcb_normalize_list identifier "$3") || exit 1
	devices=$(xcb_normalize_list device "$4") || exit 1
	umask 077
	runtime=$(xcb_runtime_directory) || exit 1
	count=0
	for directory in "$runtime/"network.*; do
		[ -e "$directory" ] || [ -L "$directory" ] || continue
		xcb_private_directory "$directory" || exit 1
		count=$((count + 1))
	done
	[ "$count" -lt 8 ] && xcb_state_budget "$runtime" || {
		xcb_state_error 'Discard unused network previews before preparing another.'; exit 1;
	}
	work=$(mktemp -d "$runtime/network.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	trap 'exit 1' HUP INT TERM
	mkdir -m 700 "$work/resources" || exit 1
	xcb_discover_configs "$work" && xcb_discover_live "$work" > "$work/live" || {
		xcb_state_error 'Network discovery failed. Check saved and pending configuration.'; exit 1;
	}
	xcb_discover_leases "$work" > "$work/leases.raw" || exit 1
	xcb_network_owned "$work" || exit 1
	if [ "$mode" = managed ]; then
		xcb_resource_target file "$selection/client.ovpn" || exit 1
		profile=$XCB_PROFILE_DIR/$selection/client.ovpn
		xcb_private_directory "$XCB_PROFILE_DIR/$selection" && xcb_private_file "$profile" || exit 1
		client=xcloud_client
		tun=$(xcb_vpn_file_device "$profile") || exit 1
		case "$tun" in tun_xc*) ;; *) exit 1 ;; esac
	else
		xcb_valid_identifier "$selection" && ! xcb_reserved_identifier "$selection" || exit 1
		client=$selection
		for hook in up down route_up route_pre_down ipchange; do
			value=$(xcb_table_get "$work/openvpn.table" "$client" "$hook") || exit 1
			[ -z "$value" ] || { xcb_state_error 'The existing client uses custom UCI hooks.'; exit 1; }
		done
		security=$(xcb_table_get "$work/openvpn.table" "$client" script_security) || exit 1
		case "$security" in ''|2|3) ;; *) xcb_state_error 'The existing client disables OpenWrt VPN hooks.'; exit 1 ;; esac
		dev_type=$(xcb_table_get "$work/openvpn.table" "$client" dev_type) || exit 1
		case "$dev_type" in ''|tun) ;; *) exit 1 ;; esac
		profile=$(xcb_table_get "$work/openvpn.table" "$client" config) || exit 1
		enabled=$(xcb_table_get "$work/openvpn.table" "$client" enabled) || exit 1
		enable=$(xcb_table_get "$work/openvpn.table" "$client" enable) || exit 1
		[ "$enabled" = 1 ] || [ "$enable" = 1 ] || {
			xcb_state_error 'Enable the existing OpenVPN client before selecting it.'; exit 1;
		}
		tun=$(xcb_table_get "$work/openvpn.table" "$client" dev) || exit 1
		[ -n "$tun" ] || tun=$(xcb_vpn_file_device "$profile") || exit 1
	fi
	xcb_valid_netdev "$tun" || exit 1
	case "$tun" in tun|tap*|lo|eth*|br-*) xcb_state_error 'A stable TUN device name is required.'; exit 1 ;; esac
	xcb_config_file "$profile" || exit 1
	cp -- "$profile" "$work/profile.source" || exit 1
	if [ "$mode" = managed ] && [ -e "$XCB_SYS_CLASS_NET/$tun" ]; then
		confirmed=$(xcb_tx_pointer confirmed) && xcb_tx_load "$confirmed" || {
			xcb_state_error 'The imported TUN device name is already in use.'; exit 1;
		}
		key=$(xcb_tx_key section openvpn.xcloud_client) || exit 1
		xcb_private_file "$tx/manifest/$key/applied" || exit 1
	fi
	# audit without rewriting an existing client's profile or hooks
	: > "$work/external-files"
	audit_external=0
	managed_credentials=$XCB_PROFILE_DIR/$selection/credentials
	[ "$mode" != external ] || audit_external=1
	[ "$mode" != external ] || managed_credentials=''
	LC_ALL=C awk -v mode=audit -v device="$tun" -v credentials="$work/credentials" \
		-v audit_external="$audit_external" -v references="$work/external-files" \
		-v managed_credentials="$managed_credentials" -v audit_dev_type="${dev_type:-}" \
		-v output="$work/audited.ovpn" -v summary="$work/vpn.summary" \
		-f "$XCB_LIBRARY_DIR/profile.awk" "$work/profile.source" || exit 1
	while IFS= read -r reference; do
		xcb_config_file "$reference" || {
			xcb_state_error 'An existing VPN certificate or key file is missing or unsafe.'; exit 1;
		}
	done < "$work/external-files"
	if [ "$mode" = managed ] && grep -qx 'auth_required=1' "$work/vpn.summary"; then
		xcb_private_file "$XCB_PROFILE_DIR/$selection/credentials" || {
			xcb_state_error 'Enter credentials for the imported profile first.'; exit 1;
		}
		LC_ALL=C awk 'length($0) < 1 || length($0) > 127 || /[\r\t]/ { bad = 1 }
			END { exit (bad || NR != 2) }' "$XCB_PROFILE_DIR/$selection/credentials" || exit 1
	fi
	# all configured clients count, including disabled clients that may start later
	awk -F '\t' '$1 == "S" && $3 == "openvpn" { print $4 }' "$work/openvpn.table" > "$work/clients"
	while IFS= read -r other; do
		xcb_valid_identifier "$other" || { xcb_state_error 'Existing VPN clients need explicit names.'; exit 1; }
		[ "$other" != "$client" ] || continue
		other_dev=$(xcb_table_get "$work/openvpn.table" "$other" dev) || exit 1
		other_path=$(xcb_table_get "$work/openvpn.table" "$other" config) || exit 1
		if [ -z "$other_dev" ]; then
			other_dev=$(xcb_vpn_file_device "$other_path") || {
				xcb_state_error 'Give each existing OpenVPN client a stable explicit device name.'; exit 1;
			}
		fi
		xcb_valid_netdev "$other_dev" && [ "$other_dev" != tun ] || exit 1
		[ "$other_dev" != "$tun" ] || { xcb_state_error 'Another OpenVPN client uses the selected TUN device.'; exit 1; }
	done < "$work/clients"
	for path in "$XCB_OPENVPN_DIR/"*.conf; do
		[ -e "$path" ] || [ -L "$path" ] || continue
		[ "$path" != "$profile" ] || continue
		other_dev=$(xcb_vpn_file_device "$path") || {
			xcb_state_error 'A standalone OpenVPN profile has no supported stable device.'; exit 1;
		}
		[ "$other_dev" != "$tun" ] || { xcb_state_error 'A standalone OpenVPN profile uses the selected TUN device.'; exit 1; }
	done
	for name in sources leases lan_networks lan_subnets lan_zones; do : > "$work/$name"; done
	LC_ALL=C awk -v out="$work" -v mode="$mode" -v client="$client" -v tun="$tun" \
		-v profile="$profile" -v networks="$networks" -v devices="$devices" -v leasefile="$XCB_LEASE_FILE" \
		-f "$XCB_LIBRARY_DIR/network.awk" "$work/"*.table "$work/live" "$work/leases.raw" "$work/vpn.summary" || exit 1
	for name in sources leases lan_networks lan_subnets lan_zones; do
		sort -u "$work/$name" > "$work/sorted" && mv "$work/sorted" "$work/$name" || exit 1
	done
	for resource in "$work/resources/"*; do
		[ -e "$resource" ] || continue
		target=${resource##*/}
		xcb_resource_target section "$target" || exit 1
		{ printf 'present\n'; cat "$resource"; } > "$work/proposed" || exit 1
		xcb_resource_validate section "$target" "$work/proposed" "$work" || exit 1
		xcb_resource_read section "$target" "$work/current" "$work" || exit 1
		if [ "$(head -n 1 "$work/current")" = present ]; then
			confirmed=$(xcb_tx_pointer confirmed) && xcb_tx_load "$confirmed" || exit 1
			key=$(xcb_tx_key section "$target") || exit 1
			xcb_private_file "$tx/manifest/$key/applied" && cmp -s "$tx/manifest/$key/applied" "$work/current" || {
				xcb_state_error 'A reserved network section already exists without matching ownership.'; exit 1;
			}
		fi
	done
	cmp -s "$profile" "$work/profile.source" || exit 1
	xcb_state_mark "$work/profile_path" "$profile" || exit 1
	xcb_state_budget "$runtime" || exit 1
	printf '%s\n' "$work"
	trap - EXIT
)

xcb_network_enqueue() (
	[ "$#" -eq 2 ] && [ "$(id -u)" -eq 0 ] && xcb_state_id "$1" && xcb_private_directory "$2" || exit 1
	id=$1 plan=$2
	xcb_private_directory "$plan/resources" || exit 1
	for package in network firewall openvpn dhcp; do
		xcb_private_file "$plan/$package.source" && xcb_config_file "$XCB_CONFIG_DIR/$package" &&
			xcb_uci_clean "$package" && cmp -s "$plan/$package.source" "$XCB_CONFIG_DIR/$package" || {
			xcb_state_error 'Network configuration changed. Prepare it again.'; exit 1;
		}
	done
	profile=$(xcb_state_read "$plan/profile_path") && xcb_config_file "$profile" || exit 1
	cmp -s "$profile" "$plan/profile.source" || exit 1
	for resource in "$plan/resources/"*; do
		[ -e "$resource" ] || continue
		xcb_private_file "$resource" || exit 1
		xcb_transaction add "$id" section "${resource##*/}" present < "$resource" || exit 1
	done
)

# call only after journaled configuration is installed, before checking PBR
xcb_vpn_attach() (
	[ "$#" -eq 3 ] && [ "$(id -u)" -eq 0 ] || exit 1
	id=$1 logical=$2 tun=$3
	[ "$logical" = xcloud_vpn ] && xcb_valid_netdev "$tun" && xcb_tx_pending "$id" || exit 1
	[ "$(xcb_state_read "$tx/state")" = applied ] || exit 1
	xcb_tx_expired && exit 1
	key=$(xcb_tx_key section network.xcloud_vpn) || exit 1
	xcb_private_file "$tx/manifest/$key/applied" || exit 1
	printf "present\nconfig interface 'xcloud_vpn'\n\toption proto 'none'\n\toption auto '1'\n" > "$tx/work/attach.expected" || exit 1
	cmp -s "$tx/manifest/$key/applied" "$tx/work/attach.expected" || exit 1
	xcb_resource_read section network.xcloud_vpn "$tx/work/attach.current" "$tx/work" || exit 1
	cmp -s "$tx/work/attach.current" "$tx/work/attach.expected" || exit 1
	flags=$(cat "$XCB_SYS_CLASS_NET/$tun/tun_flags" 2>/dev/null) || exit 1
	case "$flags" in 0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]) ;; *) exit 1 ;; esac
	[ "$((flags & 3))" -eq 1 ] || exit 1
	before=$(ip -4 -o address show dev "$tun" scope global) || exit 1
	[ -n "$before" ] || exit 1
	ip -o link show dev "$tun" | grep -Eq '<([^>]*,)?UP(,|>)' || exit 1
	# the external flag keeps netifd from flushing OpenVPN's address
	ubus -t 5 call "network.interface.$logical" add_device \
		"{\"name\":\"$tun\",\"link-ext\":true}" >/dev/null 2>&1 || exit 1
	after=$(ip -4 -o address show dev "$tun" scope global) || exit 1
	[ "$before" = "$after" ] || {
		xcb_state_error 'The VPN address changed during external attachment.'; exit 1;
	}
)

xcb_network_discard() (
	[ "$#" -eq 1 ] && [ "$(id -u)" -eq 0 ] || exit 1
	runtime=$(xcb_runtime_directory) || exit 1
	[ "${1%/*}" = "$runtime" ] || exit 1
	name=${1##*/}
	case "$name" in network.????????) ;; *) exit 1 ;; esac
	case "${name#network.}" in *[!a-zA-Z0-9]*) exit 1 ;; esac
	xcb_private_directory "$1" || exit 1
	rm -rf -- "$1"
)
