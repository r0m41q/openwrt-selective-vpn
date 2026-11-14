#!/bin/sh

xcb_service() (
	[ "$#" -ge 2 ] || exit 1
	case "$*" in
		'openvpn start xcloud_client'|'openvpn stop xcloud_client'|'pbr reload'|'pbr stop'|'pbr running'|'pbr version'|'firewall reload') ;;
		*) exit 1 ;;
	esac
	# the helper retains our locks until the bounded service group exits
	setsid /bin/sh "$XCB_LIBRARY_DIR/service-run" "$@" >/dev/null 2>&1
)

xcb_runtime_capture() (
	[ "$#" -eq 2 ] && xcb_private_directory "$1" && xcb_valid_ipv4 "$2" || exit 1
	work=$1 peer=$2
	for family in 4 6; do
		xcb_ip "-$family" -o route show table main > "$work/routes$family" || exit 1
		[ "$(wc -c < "$work/routes$family")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
	done
	xcb_ip -4 route get "$peer" > "$work/management" || exit 1
	[ -s "$work/management" ] && [ "$(wc -c < "$work/management")" -le 4096 ] || exit 1
	for key in ipv4/ip_forward ipv6/conf/all/forwarding; do
		value=$(cat "$XCB_PROC_DIR/sys/net/$key") || exit 1
		xcb_valid_bool "$value" || exit 1
		name=$(printf '%s' "$key" | tr / _)
		xcb_state_mark "$work/$name" "$value" || exit 1
	done
	xcb_state_mark "$work/peer" "$peer"
)

xcb_forward_restore() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	for key in ipv4/ip_forward ipv6/conf/all/forwarding; do
		name=$(printf '%s' "$key" | tr / _)
		value=$(xcb_state_read "$1/$name") && xcb_valid_bool "$value" || exit 1
		current=$(cat "$XCB_PROC_DIR/sys/net/$key") || exit 1
		[ "$current" = "$value" ] || printf '%s\n' "$value" > "$XCB_PROC_DIR/sys/net/$key" || exit 1
		[ "$(cat "$XCB_PROC_DIR/sys/net/$key")" = "$value" ] || exit 1
	done
)

xcb_runtime_check() (
	[ "$#" -eq 3 ] && xcb_private_directory "$1" && xcb_valid_netdev "$2" || exit 1
	work=$1 tun=$2 eligible=$3
	old_tun=''
	[ ! -e "$work/before.device" ] || old_tun=$(xcb_state_read "$work/before.device") || exit 1
	xcb_private_file "$eligible" || exit 1
	for family in 4 6; do
		xcb_ip "-$family" -o route show table main > "$work/current$family" || exit 1
		[ "$(wc -c < "$work/current$family")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
		awk -v before="$work/routes$family" -v eligible="$eligible" -v tun="$tun" -v old_tun="$old_tun" -v family="$family" \
			-f "$XCB_LIBRARY_DIR/route-check.awk" "$eligible" "$work/routes$family" "$work/current$family" || {
			xcb_state_error 'WAN or local routes changed during activation.'; exit 1;
		}
	done
	peer=$(xcb_state_read "$work/peer") && xcb_valid_ipv4 "$peer" || exit 1
	xcb_ip -4 route get "$peer" > "$work/management.current" || exit 1
	# route-get's cache line can change between calls
	awk 'NR == 1 { print; exit }' "$work/management" > "$work/management.before"
	awk 'NR == 1 { print; exit }' "$work/management.current" > "$work/management.after"
	cmp -s "$work/management.before" "$work/management.after" || {
		xcb_state_error 'The management return route changed.'; exit 1;
	}
	for key in ipv4/ip_forward ipv6/conf/all/forwarding; do
		name=$(printf '%s' "$key" | tr / _)
		[ "$(cat "$XCB_PROC_DIR/sys/net/$key")" = "$(xcb_state_read "$work/$name")" ] || exit 1
	done
)

xcb_vpn_ready() (
	[ "$#" -eq 3 ] && xcb_private_directory "$1" && xcb_valid_identifier "$2" && xcb_valid_netdev "$3" || exit 1
	work=$1 client=$2 tun=$3
	ubus -t 5 call service list '{"name":"openvpn"}' > "$work/openvpn.json" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/openvpn.json")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
	base="@.openvpn.instances.$client"
	[ "$(xcb_json_field "$work/openvpn.json" "$base.running")" = true ] || exit 1
	pid=$(xcb_json_field "$work/openvpn.json" "$base.pid") || exit 1
	xcb_valid_uint "$pid" 999999999 && [ "$pid" -gt 1 ] && kill -0 "$pid" 2>/dev/null || exit 1
	[ "$(readlink "$XCB_PROC_DIR/$pid/exe")" = /usr/sbin/openvpn ] || exit 1
	flags=$(cat "$XCB_SYS_CLASS_NET/$tun/tun_flags" 2>/dev/null) || exit 1
	case "$flags" in 0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]) ;; *) exit 1 ;; esac
	[ "$((flags & 3))" -eq 1 ] || exit 1
	xcb_ip -o link show dev "$tun" | grep -Eq '<([^>]*,)?UP(,|>)' || exit 1
	xcb_ip -4 -o address show dev "$tun" scope global > "$work/vpn.address" || exit 1
	[ -s "$work/vpn.address" ] || exit 1
	addresses=$(awk '$3 == "inet" { print $4 }' "$work/vpn.address") || exit 1
	[ -n "$addresses" ] || exit 1
	for address in $addresses; do
		xcb_valid_cidr "$address" && [ "${address##*/}" -ge 8 ] || exit 1
		first=${address%%.*}
		[ "$first" -gt 0 ] && [ "$first" -lt 224 ] && [ "$first" != 127 ] || exit 1
	done
	# IPv4 address presence alone does not establish a live VPN process
	tr '\000' '\n' < "$XCB_PROC_DIR/$pid/cmdline" > "$work/vpn.command" || exit 1
	awk -v tun="$tun" 'last == "--dev" && $0 == tun { found=1 } { last=$0 }
		END { exit !found }' "$work/vpn.command"
)

xcb_pbr_health() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	work=$1
	xcb_service pbr running || exit 1
	ubus -t 5 call service list '{"name":"pbr"}' > "$work/pbr.json" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/pbr.json")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
	gateways=$(xcb_json_field "$work/pbr.json" '@.pbr.instances.main.data.gateways[*].name') || exit 1
	[ -n "$gateways" ] || exit 1
	errors=$(xcb_json_field "$work/pbr.json" '@.pbr.instances.main.data.errors[*].code' || :)
	[ -z "$errors" ]
)

xcb_pbr_ready() (
	[ "$#" -eq 3 ] && xcb_valid_interface "$2" && xcb_valid_netdev "$3" || exit 1
	work=$1 logical=$2 tun=$3
	ubus -t 5 call "network.interface.$logical" status '{}' > "$work/logical.json" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/logical.json")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
	[ "$(xcb_json_field "$work/logical.json" '@.up')" = true ] &&
		[ "$(xcb_json_field "$work/logical.json" '@.l3_device')" = "$tun" ] || exit 1
	xcb_pbr_health "$work" || exit 1
	xcb_config_file "$XCB_RT_TABLES" || exit 1
	table=$(awk -v name="pbr_$logical" '$2 == name && $1 ~ /^[0-9]+$/ { print $1; found++ }
		END { if (found != 1) exit 1 }' "$XCB_RT_TABLES") || exit 1
	xcb_valid_uint "$table" 999999999 && [ "$table" -gt 0 ] || exit 1
	xcb_ip -4 route show table "$table" > "$work/pbr.routes" || exit 1
	awk -v tun="$tun" '$1 == "default" { for (i=2;i<NF;i++) if ($i=="dev" && $(i+1)==tun) found++ }
		END { exit (found != 1) }' "$work/pbr.routes" || exit 1
	xcb_ip -4 rule show > "$work/pbr.rules" || exit 1
	awk -v name="pbr_$logical" -v table="$table" '/fwmark/ { for(i=1;i<NF;i++) if($i=="lookup" && ($(i+1)==name || $(i+1)==table)) found++ }
		END { exit !found }' "$work/pbr.rules" || exit 1
	xcb_pbr_policies "$work"
)

xcb_pbr_policies() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	work=$1
	nft -j list chain inet fw4 pbr_prerouting > "$work/pbr.nft" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/pbr.nft")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
	xcb_json_field "$work/pbr.nft" '@.nftables[*].rule.comment' > "$work/pbr.comments" || exit 1
	for name in console browser custom; do
		xcb_resource_read section "pbr.xcloud_$name" "$work/policy.current" "$work" || exit 1
		case "$name" in console) label='Xbox console authentication' ;; browser) label='Browser xCloud authentication' ;; custom) label='Custom authentication destinations' ;; esac
		if [ "$(head -n 1 "$work/policy.current")" = present ]; then
			grep -qxF "$label" "$work/pbr.comments" || exit 1
		elif grep -qxF "$label" "$work/pbr.comments"; then exit 1; fi
	done
)

xcb_pbr_reload() (
	[ "$#" -eq 2 ] && xcb_private_directory "$1" || exit 1
	work=$1 action=$2
	case "$action" in reload|stop) ;; *) exit 1 ;; esac
	xcb_config_file "$XCB_CONFIG_DIR/dhcp" && xcb_uci_clean dhcp || exit 1
	cp "$XCB_CONFIG_DIR/dhcp" "$work/dhcp.before" && chmod 600 "$work/dhcp.before" || exit 1
	xcb_uci_export "$work/dhcp.before" > "$work/dhcp.export.before" || exit 1
	result=0
	xcb_service pbr "$action" || result=$?
	# PBR owns this one list entry, including on anonymous dnsmasq sections
	xcb_config_file "$XCB_CONFIG_DIR/dhcp" && xcb_uci_clean dhcp || exit 1
	cp "$XCB_CONFIG_DIR/dhcp" "$work/dhcp.after" && chmod 600 "$work/dhcp.after" || exit 1
	xcb_uci_export "$work/dhcp.after" > "$work/dhcp.export.after" || exit 1
	for version in before after; do
		awk -f "$XCB_LIBRARY_DIR/dhcp-mount.awk" "$work/dhcp.export.$version" > "$work/dhcp.check.$version" || exit 1
	done
	cmp -s "$work/dhcp.check.before" "$work/dhcp.check.after" || {
		xcb_state_error 'DNS configuration changed beyond the native PBR mount. Review the private backup.'; exit 1;
	}
	# native PBR may return a warning status; inspect its actual state below
	[ "$result" -le 1 ] || exit 1
	if [ "$action" = stop ]; then
		if xcb_service pbr running; then exit 1; fi
	fi
)

xcb_runtime_dns() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	work=$1
	xcb_config_file "$XCB_CONFIG_DIR/dhcp" && xcb_uci_clean dhcp || exit 1
	cp "$XCB_CONFIG_DIR/dhcp" "$work/dhcp.current" && chmod 600 "$work/dhcp.current" || exit 1
	xcb_uci_export "$work/dhcp.current" > "$work/dhcp.export" || exit 1
	awk -v package=dhcp -f "$XCB_LIBRARY_DIR/uci-inspect.awk" "$work/dhcp.export" > "$work/dhcp.table" || exit 1
	instance=$(xcb_state_read "$work/resolver_instance") || exit 1
	: > "$work/warnings"
	xcb_dns_check "$work" "$instance" || exit 1
	path=$(CDPATH='' cd -- "${XCB_PBR_DNS%/*}" && pwd -P)/${XCB_PBR_DNS##*/} || exit 1
	xcb_check_directory_chain "${path%/*}" && [ -f "$path" ] && [ ! -L "$path" ] || exit 1
	info=$(stat -c '%u %a %h %s' "$path") || exit 1
	set -- $info
	[ "$1" = "$(id -u)" ] && [ "$3" = 1 ] && [ "$4" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
	case "$2" in 600|640|644|660) ;; *) exit 1 ;; esac
	cp "$path" "$work/resolver.snippet" && chmod 600 "$work/resolver.snippet" || exit 1
	: > "$work/domains"
	for value in $(cat "$work/destinations"); do
		if xcb_valid_domain "$value"; then printf '%s\n' "$value" >> "$work/domains"; fi
	done
	nft -j list sets inet > "$work/resolver.nft" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/resolver.nft")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
	xcb_json_field "$work/resolver.nft" '@.nftables[*].set.name' > "$work/resolver.sets" || exit 1
	awk -v destinations="$work/domains" -v sets="$work/resolver.sets" -f "$XCB_LIBRARY_DIR/resolver-check.awk" \
		"$work/domains" "$work/resolver.sets" "$work/resolver.snippet"
)

xcb_boot_resolver_restore() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	work=$1 path=$XCB_CONFIG_DIR/dhcp
	xcb_private_file "$work/dhcp.original" && xcb_config_file "$path" && xcb_uci_clean dhcp || exit 1
	xcb_uci_export "$work/dhcp.original" > "$work/boot.original.raw" || exit 1
	awk -v keep_mount=1 -f "$XCB_LIBRARY_DIR/dhcp-mount.awk" "$work/boot.original.raw" > "$work/boot.original" || exit 1
	awk -f "$XCB_LIBRARY_DIR/dhcp-mount.awk" "$work/boot.original" > "$work/boot.original.clean" || exit 1
	# preserve a mount that existed before this transaction
	cmp -s "$work/boot.original" "$work/boot.original.clean" || exit 0
	cp "$path" "$work/boot.source" && chmod 600 "$work/boot.source" || exit 1
	xcb_uci_export "$work/boot.source" > "$work/boot.export.raw" || exit 1
	awk -v keep_mount=1 -f "$XCB_LIBRARY_DIR/dhcp-mount.awk" "$work/boot.export.raw" > "$work/boot.export" || exit 1
	awk -f "$XCB_LIBRARY_DIR/dhcp-mount.awk" "$work/boot.export" > "$work/boot.clean" || exit 1
	cmp -s "$work/boot.export" "$work/boot.clean" && exit 0
	xcb_uci_export "$work/boot.clean" > "$work/boot.checked.raw" || exit 1
	awk -v keep_mount=1 -f "$XCB_LIBRARY_DIR/dhcp-mount.awk" "$work/boot.checked.raw" > "$work/boot.checked" || exit 1
	cmp -s "$work/boot.clean" "$work/boot.checked" || exit 1
	mode=$(stat -c '%a' "$path") || exit 1
	stage=$(mktemp "$XCB_CONFIG_DIR/.xcloud.XXXXXXXX") || exit 1
	trap 'rm -f -- "$stage"' EXIT
	cat "$work/boot.clean" > "$stage" && chmod "$mode" "$stage" && sync || exit 1
	xcb_uci_clean dhcp && xcb_config_file "$path" && cmp -s "$path" "$work/boot.source" || exit 1
	mv -f -- "$stage" "$path" && sync
)
