#!/bin/sh

# source validation, private storage, recovery, profile and discovery libraries first
svpn_table_get() (
	[ "$#" -eq 3 ] || exit 1
	awk -F '\t' -v name="$2" -v key="$3" '
		$1 == "S" && $4 == name { section = $2; found++ }
		$1 == "V" { values[$2,$3] = $4 }
		END { if (found != 1) exit 1; print values[section,key] }
	' "$1"
)

svpn_vpn_file_device() (
	[ "$#" -eq 1 ] && svpn_config_file "$1" || exit 1
	LC_ALL=C awk -v mode=inventory -f "$SVPN_LIBRARY_DIR/profile.awk" "$1"
)

svpn_network_owned() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	if [ ! -e "$SVPN_PRIVATE_DIR/confirmed" ] && [ ! -L "$SVPN_PRIVATE_DIR/confirmed" ]; then exit 0; fi
	confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
	for record in "$tx/manifest"/*; do
		[ -e "$record" ] || continue
		svpn_tx_check_record "$record" || exit 1
		kind=$(svpn_state_read "$record/kind") && target=$(svpn_state_read "$record/target") || exit 1
		case "$kind:$target" in section:network.*|section:firewall.*|section:openvpn.*) ;; *) continue ;; esac
		svpn_resource_read "$kind" "$target" "$1/current" "$1" || exit 1
		cmp -s "$record/applied" "$1/current" || {
			svpn_state_error 'A managed network resource was edited outside the application.'; exit 1;
		}
	done
)

# prepare private candidates; applying them requires the recovery lifecycle
svpn_network_prepare() (
	[ "$#" -eq 4 ] && [ "$(id -u)" -eq 0 ] || exit 1
	mode=$1 selection=$2
	case "$mode" in managed|external) ;; *) exit 1 ;; esac
	networks=$(svpn_normalize_list identifier "$3") || exit 1
	devices=$(svpn_normalize_list device "$4") || exit 1
	umask 077
	runtime=$(svpn_runtime_directory) || exit 1
	count=0
	for directory in "$runtime/"network.*; do
		[ -e "$directory" ] || [ -L "$directory" ] || continue
		svpn_private_directory "$directory" || exit 1
		count=$((count + 1))
	done
	[ "$count" -lt 8 ] && svpn_state_budget "$runtime" || {
		svpn_state_error 'Discard unused network previews before preparing another.'; exit 1;
	}
	work=$(mktemp -d "$runtime/network.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	trap 'exit 1' HUP INT TERM
	mkdir -m 700 "$work/resources" || exit 1
	svpn_discover_configs "$work" && svpn_discover_live "$work" > "$work/live" || {
		svpn_state_error 'Network discovery failed. Check saved and pending configuration.'; exit 1;
	}
	svpn_discover_leases "$work" > "$work/leases.raw" || exit 1
	svpn_network_owned "$work" || exit 1
	if [ "$mode" = managed ]; then
		svpn_resource_target file "$selection/client.ovpn" || exit 1
		profile=$SVPN_PROFILE_DIR/$selection/client.ovpn
		svpn_private_directory "$SVPN_PROFILE_DIR/$selection" && svpn_private_file "$profile" || exit 1
		client=svpn_client
		tun=$(svpn_vpn_file_device "$profile") || exit 1
		case "$tun" in tun_sv*) ;; *) exit 1 ;; esac
	else
		svpn_valid_identifier "$selection" && ! svpn_reserved_identifier "$selection" || exit 1
		client=$selection
		for hook in up down route_up route_pre_down ipchange; do
			value=$(svpn_table_get "$work/openvpn.table" "$client" "$hook") || exit 1
			[ -z "$value" ] || { svpn_state_error 'The existing client uses custom UCI hooks.'; exit 1; }
		done
		security=$(svpn_table_get "$work/openvpn.table" "$client" script_security) || exit 1
		case "$security" in ''|2|3) ;; *) svpn_state_error 'The existing client disables OpenWrt VPN hooks.'; exit 1 ;; esac
		dev_type=$(svpn_table_get "$work/openvpn.table" "$client" dev_type) || exit 1
		case "$dev_type" in ''|tun) ;; *) exit 1 ;; esac
		profile=$(svpn_table_get "$work/openvpn.table" "$client" config) || exit 1
		enabled=$(svpn_table_get "$work/openvpn.table" "$client" enabled) || exit 1
		enable=$(svpn_table_get "$work/openvpn.table" "$client" enable) || exit 1
		[ "$enabled" = 1 ] || [ "$enable" = 1 ] || {
			svpn_state_error 'Enable the existing OpenVPN client before selecting it.'; exit 1;
		}
		tun=$(svpn_table_get "$work/openvpn.table" "$client" dev) || exit 1
		[ -n "$tun" ] || tun=$(svpn_vpn_file_device "$profile") || exit 1
	fi
	svpn_valid_netdev "$tun" || exit 1
	case "$tun" in tun|tap*|lo|eth*|br-*) svpn_state_error 'A stable TUN device name is required.'; exit 1 ;; esac
	svpn_config_file "$profile" || exit 1
	cp -- "$profile" "$work/profile.source" || exit 1
	if [ "$mode" = managed ] && [ -e "$SVPN_SYS_CLASS_NET/$tun" ]; then
		confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || {
			svpn_state_error 'The imported TUN device name is already in use.'; exit 1;
		}
		key=$(svpn_tx_key section openvpn.svpn_client) || exit 1
		svpn_private_file "$tx/manifest/$key/applied" || exit 1
	fi
	# audit without rewriting an existing client's profile or hooks
	: > "$work/external-files"
	audit_external=0
	managed_credentials=$SVPN_PROFILE_DIR/$selection/credentials
	[ "$mode" != external ] || audit_external=1
	[ "$mode" != external ] || managed_credentials=''
	LC_ALL=C awk -v mode=audit -v device="$tun" -v credentials="$work/credentials" \
		-v audit_external="$audit_external" -v references="$work/external-files" \
		-v managed_credentials="$managed_credentials" -v audit_dev_type="${dev_type:-}" \
		-v output="$work/audited.ovpn" -v summary="$work/vpn.summary" \
		-f "$SVPN_LIBRARY_DIR/profile.awk" "$work/profile.source" || exit 1
	while IFS= read -r reference; do
		svpn_config_file "$reference" || {
			svpn_state_error 'An existing VPN certificate or key file is missing or unsafe.'; exit 1;
		}
	done < "$work/external-files"
	if [ "$mode" = managed ] && grep -qx 'auth_required=1' "$work/vpn.summary"; then
		svpn_private_file "$SVPN_PROFILE_DIR/$selection/credentials" || {
			svpn_state_error 'Enter credentials for the imported profile first.'; exit 1;
		}
		LC_ALL=C awk 'length($0) < 1 || length($0) > 127 || /[\r\t]/ { bad = 1 }
			END { exit (bad || NR != 2) }' "$SVPN_PROFILE_DIR/$selection/credentials" || exit 1
		sha256sum "$SVPN_PROFILE_DIR/$selection/credentials" > "$work/credentials.sha256" || exit 1
	fi
	# all configured clients count, including disabled clients that may start later
	awk -F '\t' '$1 == "S" && $3 == "openvpn" { print $4 }' "$work/openvpn.table" > "$work/clients"
	while IFS= read -r other; do
		svpn_valid_identifier "$other" || { svpn_state_error 'Existing VPN clients need explicit names.'; exit 1; }
		[ "$other" != "$client" ] || continue
		other_dev=$(svpn_table_get "$work/openvpn.table" "$other" dev) || exit 1
		other_path=$(svpn_table_get "$work/openvpn.table" "$other" config) || exit 1
		if [ -z "$other_dev" ]; then
			other_dev=$(svpn_vpn_file_device "$other_path") || {
				svpn_state_error 'Give each existing OpenVPN client a stable explicit device name.'; exit 1;
			}
		fi
		svpn_valid_netdev "$other_dev" && [ "$other_dev" != tun ] || exit 1
		[ "$other_dev" != "$tun" ] || { svpn_state_error 'Another OpenVPN client uses the selected TUN device.'; exit 1; }
	done < "$work/clients"
	for path in "$SVPN_OPENVPN_DIR/"*.conf; do
		[ -e "$path" ] || [ -L "$path" ] || continue
		[ "$path" != "$profile" ] || continue
		other_dev=$(svpn_vpn_file_device "$path") || {
			svpn_state_error 'A standalone OpenVPN profile has no supported stable device.'; exit 1;
		}
		[ "$other_dev" != "$tun" ] || { svpn_state_error 'A standalone OpenVPN profile uses the selected TUN device.'; exit 1; }
	done
	for name in sources leases lan_networks lan_subnets lan_zones; do : > "$work/$name"; done
	owned_zone=0
	if [ -e "$SVPN_PRIVATE_DIR/confirmed" ]; then
		confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
		key=$(svpn_tx_key section firewall.svpn_zone) || exit 1
		if [ -f "$tx/manifest/$key/applied" ] && [ "$(head -n 1 "$tx/manifest/$key/applied")" = present ]; then owned_zone=1; fi
	fi
	LC_ALL=C awk -v out="$work" -v mode="$mode" -v client="$client" -v tun="$tun" \
		-v owned_zone="$owned_zone" \
		-v profile="$profile" -v networks="$networks" -v devices="$devices" -v leasefile="$SVPN_LEASE_FILE" \
		-f "$SVPN_LIBRARY_DIR/network.awk" "$work/"*.table "$work/live" "$work/leases.raw" "$work/vpn.summary" || exit 1
	for name in sources leases lan_networks lan_subnets lan_zones; do
		sort -u "$work/$name" > "$work/sorted" && mv "$work/sorted" "$work/$name" || exit 1
	done
	for resource in "$work/resources/"*; do
		[ -e "$resource" ] || continue
		target=${resource##*/}
		svpn_resource_target section "$target" || exit 1
		{ printf 'present\n'; cat "$resource"; } > "$work/proposed" || exit 1
		svpn_resource_validate section "$target" "$work/proposed" "$work" || exit 1
		svpn_resource_read section "$target" "$work/current" "$work" || exit 1
		if [ "$(head -n 1 "$work/current")" = present ]; then
			confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
			key=$(svpn_tx_key section "$target") || exit 1
			svpn_private_file "$tx/manifest/$key/applied" && cmp -s "$tx/manifest/$key/applied" "$work/current" || {
				svpn_state_error 'A reserved network section already exists without matching ownership.'; exit 1;
			}
		fi
	done
	cmp -s "$profile" "$work/profile.source" || exit 1
	svpn_state_mark "$work/profile_path" "$profile" || exit 1
	svpn_state_budget "$runtime" || exit 1
	printf '%s\n' "$work"
	trap - EXIT
)

svpn_network_recheck() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	umask 077
	plan=$1
	svpn_private_directory "$plan/resources" || exit 1
	for package in network firewall openvpn dhcp; do
		svpn_private_file "$plan/$package.source" && svpn_config_file "$SVPN_CONFIG_DIR/$package" &&
			svpn_uci_clean "$package" && cmp -s "$plan/$package.source" "$SVPN_CONFIG_DIR/$package" || {
			svpn_state_error 'Network configuration changed. Prepare it again.'; exit 1;
		}
	done
	profile=$(svpn_state_read "$plan/profile_path") && svpn_config_file "$profile" || exit 1
	cmp -s "$profile" "$plan/profile.source" || exit 1
	if [ -e "$plan/credentials.sha256" ]; then
		svpn_private_file "$plan/credentials.sha256" && svpn_private_file "${profile%/*}/credentials" || exit 1
		sha256sum "${profile%/*}/credentials" > "$plan/credentials.current" || exit 1
		cmp -s "$plan/credentials.sha256" "$plan/credentials.current" || exit 1
	fi
)

svpn_network_enqueue() (
	[ "$#" -eq 2 ] && [ "$(id -u)" -eq 0 ] && svpn_state_id "$1" && svpn_private_directory "$2" || exit 1
	id=$1 plan=$2
	svpn_network_recheck "$plan" || exit 1
	for resource in "$plan/resources/"*; do
		[ -e "$resource" ] || continue
		svpn_private_file "$resource" || exit 1
		svpn_transaction add "$id" section "${resource##*/}" present < "$resource" || exit 1
	done
)

# call only after journaled configuration is installed, before checking PBR
svpn_vpn_attach() (
	[ "$#" -eq 3 ] && [ "$(id -u)" -eq 0 ] || exit 1
	id=$1 logical=$2 tun=$3
	[ "$logical" = svpn_vpn ] && svpn_valid_netdev "$tun" && svpn_tx_pending "$id" || exit 1
	state=$(svpn_state_read "$tx/state") || exit 1
	case "$state" in applied|awaiting_confirmation) svpn_tx_expired && exit 1 ;; recovering|runtime_recovery) ;; *) exit 1 ;; esac
	key=$(svpn_tx_key section network.svpn_vpn) || exit 1
	svpn_private_file "$tx/manifest/$key/applied" || exit 1
	printf "present\nconfig interface 'svpn_vpn'\n\toption proto 'none'\n\toption auto '1'\n" > "$tx/work/attach.expected" || exit 1
	case "$state" in
		applied|awaiting_confirmation) cmp -s "$tx/manifest/$key/applied" "$tx/work/attach.expected" || exit 1 ;;
		recovering|runtime_recovery)
			found=0
			for record in "$tx/changes/"*; do
				[ -e "$record" ] || continue
				[ "$(svpn_state_read "$record/target")" = network.svpn_vpn ] || continue
				cmp -s "$record/original" "$tx/work/attach.expected" && found=1
			done
			[ "$found" = 1 ] || cmp -s "$tx/manifest/$key/applied" "$tx/work/attach.expected" || exit 1 ;;
	esac
	svpn_resource_read section network.svpn_vpn "$tx/work/attach.current" "$tx/work" || exit 1
	cmp -s "$tx/work/attach.current" "$tx/work/attach.expected" || exit 1
	flags=$(cat "$SVPN_SYS_CLASS_NET/$tun/tun_flags" 2>/dev/null) || exit 1
	case "$flags" in 0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]) ;; *) exit 1 ;; esac
	[ "$((flags & 3))" -eq 1 ] || exit 1
	before=$(svpn_ip -4 -o address show dev "$tun" scope global) || exit 1
	[ -n "$before" ] || exit 1
	svpn_ip -o link show dev "$tun" | grep -Eq '<([^>]*,)?UP(,|>)' || exit 1
	# the external flag keeps netifd from flushing OpenVPN's address
	ubus -t 5 call "network.interface.$logical" add_device \
		"{\"name\":\"$tun\",\"link-ext\":true}" >/dev/null 2>&1 || exit 1
	after=$(svpn_ip -4 -o address show dev "$tun" scope global) || exit 1
	[ "$before" = "$after" ] || {
		svpn_state_error 'The VPN address changed during external attachment.'; exit 1;
	}
)

svpn_network_discard() (
	[ "$#" -eq 1 ] && [ "$(id -u)" -eq 0 ] || exit 1
	runtime=$(svpn_runtime_directory) || exit 1
	[ "${1%/*}" = "$runtime" ] || exit 1
	name=${1##*/}
	case "$name" in network.????????) ;; *) exit 1 ;; esac
	case "${name#network.}" in *[!a-zA-Z0-9]*) exit 1 ;; esac
	svpn_private_directory "$1" || exit 1
	rm -rf -- "$1"
)
