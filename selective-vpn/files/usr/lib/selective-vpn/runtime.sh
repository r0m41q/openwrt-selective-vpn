#!/bin/sh

svpn_service() (
	[ "$#" -ge 2 ] || exit 1
	case "$*" in
		'openvpn start svpn_client'|'openvpn stop svpn_client'|'pbr reload'|'pbr stop'|'pbr running'|'pbr version'|'firewall reload') ;;
		*) exit 1 ;;
	esac
	# the helper retains our locks until the bounded service group exits
	setsid /bin/sh "$SVPN_LIBRARY_DIR/service-run" "$@" >/dev/null 2>&1
)

svpn_runtime_capture() (
	[ "$#" -eq 2 ] && svpn_private_directory "$1" && svpn_valid_ipv4 "$2" || exit 1
	work=$1 peer=$2
	for family in 4 6; do
		svpn_ip "-$family" -o route show table main > "$work/routes$family" || exit 1
		[ "$(wc -c < "$work/routes$family")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
	done
	svpn_ip -4 route get "$peer" > "$work/management" || exit 1
	[ -s "$work/management" ] && [ "$(wc -c < "$work/management")" -le 4096 ] || exit 1
	for key in ipv4/ip_forward ipv6/conf/all/forwarding; do
		value=$(cat "$SVPN_PROC_DIR/sys/net/$key") || exit 1
		svpn_valid_bool "$value" || exit 1
		name=$(printf '%s' "$key" | tr / _)
		svpn_state_mark "$work/$name" "$value" || exit 1
	done
	svpn_state_mark "$work/peer" "$peer"
)

svpn_forward_restore() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	for key in ipv4/ip_forward ipv6/conf/all/forwarding; do
		name=$(printf '%s' "$key" | tr / _)
		value=$(svpn_state_read "$1/$name") && svpn_valid_bool "$value" || exit 1
		current=$(cat "$SVPN_PROC_DIR/sys/net/$key") || exit 1
		[ "$current" = "$value" ] || printf '%s\n' "$value" > "$SVPN_PROC_DIR/sys/net/$key" || exit 1
		[ "$(cat "$SVPN_PROC_DIR/sys/net/$key")" = "$value" ] || exit 1
	done
)

svpn_runtime_check() (
	[ "$#" -eq 3 ] && svpn_private_directory "$1" && svpn_valid_netdev "$2" || exit 1
	work=$1 tun=$2 eligible=$3
	old_tun=''
	[ ! -e "$work/before.device" ] || old_tun=$(svpn_state_read "$work/before.device") || exit 1
	svpn_private_file "$eligible" || exit 1
	for family in 4 6; do
		svpn_ip "-$family" -o route show table main > "$work/current$family" || exit 1
		[ "$(wc -c < "$work/current$family")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
		awk -v before="$work/routes$family" -v eligible="$eligible" -v tun="$tun" -v old_tun="$old_tun" -v family="$family" \
			-f "$SVPN_LIBRARY_DIR/route-check.awk" "$eligible" "$work/routes$family" "$work/current$family" || {
			svpn_state_error 'WAN or local routes changed during activation.'; exit 1;
		}
	done
	peer=$(svpn_state_read "$work/peer") && svpn_valid_ipv4 "$peer" || exit 1
	svpn_ip -4 route get "$peer" > "$work/management.current" || exit 1
	# route-get's cache line can change between calls
	awk 'NR == 1 { print; exit }' "$work/management" > "$work/management.before"
	awk 'NR == 1 { print; exit }' "$work/management.current" > "$work/management.after"
	cmp -s "$work/management.before" "$work/management.after" || {
		svpn_state_error 'The management return route changed.'; exit 1;
	}
	for key in ipv4/ip_forward ipv6/conf/all/forwarding; do
		name=$(printf '%s' "$key" | tr / _)
		[ "$(cat "$SVPN_PROC_DIR/sys/net/$key")" = "$(svpn_state_read "$work/$name")" ] || exit 1
	done
)

svpn_vpn_ready() (
	[ "$#" -eq 3 ] && svpn_private_directory "$1" && svpn_valid_identifier "$2" && svpn_valid_netdev "$3" || exit 1
	work=$1 client=$2 tun=$3
	ubus -t 5 call service list '{"name":"openvpn"}' > "$work/openvpn.json" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/openvpn.json")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
	base="@.openvpn.instances.$client"
	[ "$(svpn_json_field "$work/openvpn.json" "$base.running")" = true ] || exit 1
	pid=$(svpn_json_field "$work/openvpn.json" "$base.pid") || exit 1
	svpn_valid_uint "$pid" 999999999 && [ "$pid" -gt 1 ] && kill -0 "$pid" 2>/dev/null || exit 1
	[ "$(readlink "$SVPN_PROC_DIR/$pid/exe")" = /usr/sbin/openvpn ] || exit 1
	flags=$(cat "$SVPN_SYS_CLASS_NET/$tun/tun_flags" 2>/dev/null) || exit 1
	case "$flags" in 0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]) ;; *) exit 1 ;; esac
	[ "$((flags & 3))" -eq 1 ] || exit 1
	svpn_ip -o link show dev "$tun" | grep -Eq '<([^>]*,)?UP(,|>)' || exit 1
	svpn_ip -4 -o address show dev "$tun" scope global > "$work/vpn.address" || exit 1
	[ -s "$work/vpn.address" ] || exit 1
	addresses=$(awk '$3 == "inet" { print $4 }' "$work/vpn.address") || exit 1
	[ -n "$addresses" ] || exit 1
	for address in $addresses; do
		svpn_valid_cidr "$address" && [ "${address##*/}" -ge 8 ] || exit 1
		first=${address%%.*}
		[ "$first" -gt 0 ] && [ "$first" -lt 224 ] && [ "$first" != 127 ] || exit 1
	done
	# IPv4 address presence alone does not establish a live VPN process
	tr '\000' '\n' < "$SVPN_PROC_DIR/$pid/cmdline" > "$work/vpn.command" || exit 1
	awk -v tun="$tun" 'last == "--dev" && $0 == tun { found=1 } { last=$0 }
		END { exit !found }' "$work/vpn.command"
)

svpn_pbr_health() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	work=$1
	svpn_service pbr running || exit 1
	ubus -t 5 call service list '{"name":"pbr"}' > "$work/pbr.json" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/pbr.json")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
	gateways=$(svpn_json_field "$work/pbr.json" '@.pbr.instances.main.data.gateways[*].name') || exit 1
	[ -n "$gateways" ] || exit 1
	errors=$(svpn_json_field "$work/pbr.json" '@.pbr.instances.main.data.errors[*].code' || :)
	[ -z "$errors" ]
)

svpn_pbr_ready() (
	[ "$#" -eq 3 ] && svpn_valid_interface "$2" && svpn_valid_netdev "$3" || exit 1
	work=$1 logical=$2 tun=$3
	ubus -t 5 call "network.interface.$logical" status '{}' > "$work/logical.json" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/logical.json")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
	[ "$(svpn_json_field "$work/logical.json" '@.up')" = true ] &&
		[ "$(svpn_json_field "$work/logical.json" '@.l3_device')" = "$tun" ] || exit 1
	svpn_pbr_health "$work" || exit 1
	svpn_config_file "$SVPN_RT_TABLES" || exit 1
	table=$(awk -v name="pbr_$logical" '$2 == name && $1 ~ /^[0-9]+$/ { print $1; found++ }
		END { if (found != 1) exit 1 }' "$SVPN_RT_TABLES") || exit 1
	svpn_valid_uint "$table" 999999999 && [ "$table" -gt 0 ] || exit 1
	svpn_ip -4 route show table "$table" > "$work/pbr.routes" || exit 1
	awk -v tun="$tun" '$1 == "default" { for (i=2;i<NF;i++) if ($i=="dev" && $(i+1)==tun) found++ }
		END { exit (found != 1) }' "$work/pbr.routes" || exit 1
	svpn_ip -4 rule show > "$work/pbr.rules" || exit 1
	awk -v name="pbr_$logical" -v table="$table" '/fwmark/ { for(i=1;i<NF;i++) if($i=="lookup" && ($(i+1)==name || $(i+1)==table)) found++ }
		END { exit !found }' "$work/pbr.rules" || exit 1
	svpn_pbr_policies "$work"
)

svpn_pbr_policies() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	work=$1
	nft -j list chain inet fw4 pbr_prerouting > "$work/pbr.nft" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/pbr.nft")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
	svpn_json_field "$work/pbr.nft" '@.nftables[*].rule.comment' > "$work/pbr.comments" || exit 1
	svpn_config_file "$SVPN_CONFIG_DIR/pbr" && svpn_uci_clean pbr || exit 1
	svpn_uci_export "$SVPN_CONFIG_DIR/pbr" > "$work/policies.export" || exit 1
	awk -v package=pbr -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/policies.export" > "$work/policies.table" || exit 1
	awk -F '\t' '$1=="S" { own[$2]=($3=="policy" && $4 ~ /^svpn_route_[a-zA-Z0-9_]+$/) }
		$1=="V" && own[$2] { v[$2,$3]=$4 }
		END { for(s in own) if(own[s] && v[s,"enabled"]!="0" && v[s,"chain"] ~ /^(|prerouting)$/ && v[s,"name"]!="") print v[s,"name"] }' \
		"$work/policies.table" > "$work/route.labels" || exit 1
	while IFS= read -r label; do
		grep -qxF "$label" "$work/pbr.comments" || exit 1
	done < "$work/route.labels"
	while IFS= read -r label; do
		case "$label" in 'Selective VPN: '*) grep -qxF "$label" "$work/route.labels" || exit 1 ;; esac
	done < "$work/pbr.comments"
)

svpn_pbr_reload() (
	[ "$#" -eq 2 ] && svpn_private_directory "$1" || exit 1
	work=$1 action=$2
	case "$action" in reload|stop) ;; *) exit 1 ;; esac
	svpn_config_file "$SVPN_CONFIG_DIR/dhcp" && svpn_uci_clean dhcp || exit 1
	cp "$SVPN_CONFIG_DIR/dhcp" "$work/dhcp.before" && chmod 600 "$work/dhcp.before" || exit 1
	svpn_uci_export "$work/dhcp.before" > "$work/dhcp.export.before" || exit 1
	result=0
	svpn_service pbr "$action" || result=$?
	# PBR owns this one list entry, including on anonymous dnsmasq sections
	svpn_config_file "$SVPN_CONFIG_DIR/dhcp" && svpn_uci_clean dhcp || exit 1
	cp "$SVPN_CONFIG_DIR/dhcp" "$work/dhcp.after" && chmod 600 "$work/dhcp.after" || exit 1
	svpn_uci_export "$work/dhcp.after" > "$work/dhcp.export.after" || exit 1
	for version in before after; do
		awk -f "$SVPN_LIBRARY_DIR/dhcp-mount.awk" "$work/dhcp.export.$version" > "$work/dhcp.check.$version" || exit 1
	done
	cmp -s "$work/dhcp.check.before" "$work/dhcp.check.after" || {
		svpn_state_error 'DNS configuration changed beyond the native PBR mount. Review the private backup.'; exit 1;
	}
	# native PBR may return a warning status; inspect its actual state below
	[ "$result" -le 1 ] || exit 1
	if [ "$action" = stop ]; then
		if svpn_service pbr running; then exit 1; fi
	fi
)

svpn_runtime_dns() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	work=$1
	svpn_config_file "$SVPN_CONFIG_DIR/dhcp" && svpn_uci_clean dhcp || exit 1
	cp "$SVPN_CONFIG_DIR/dhcp" "$work/dhcp.current" && chmod 600 "$work/dhcp.current" || exit 1
	svpn_uci_export "$work/dhcp.current" > "$work/dhcp.export" || exit 1
	awk -v package=dhcp -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/dhcp.export" > "$work/dhcp.table" || exit 1
	instance=$(svpn_state_read "$work/resolver_instance") || exit 1
	: > "$work/warnings"
	svpn_dns_check "$work" "$instance" || exit 1
	path=$(CDPATH='' cd -- "${SVPN_PBR_DNS%/*}" && pwd -P)/${SVPN_PBR_DNS##*/} || exit 1
	svpn_check_directory_chain "${path%/*}" && [ -f "$path" ] && [ ! -L "$path" ] || exit 1
	info=$(stat -c '%u %a %h %s' "$path") || exit 1
	set -- $info
	[ "$1" = "$(id -u)" ] && [ "$3" = 1 ] && [ "$4" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
	case "$2" in 600|640|644|660) ;; *) exit 1 ;; esac
	cp "$path" "$work/resolver.snippet" && chmod 600 "$work/resolver.snippet" || exit 1
	: > "$work/domains"
	for value in $(cat "$work/destinations"); do
		if svpn_valid_domain "$value"; then printf '%s\n' "$value" >> "$work/domains"; fi
	done
	nft -j list sets inet > "$work/resolver.nft" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/resolver.nft")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
	svpn_json_field "$work/resolver.nft" '@.nftables[*].set.name' > "$work/resolver.sets" || exit 1
	awk -v destinations="$work/domains" -v sets="$work/resolver.sets" -f "$SVPN_LIBRARY_DIR/resolver-check.awk" \
		"$work/domains" "$work/resolver.sets" "$work/resolver.snippet"
)

svpn_boot_resolver_restore() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	work=$1 path=$SVPN_CONFIG_DIR/dhcp
	svpn_private_file "$work/dhcp.original" && svpn_config_file "$path" && svpn_uci_clean dhcp || exit 1
	svpn_uci_export "$work/dhcp.original" > "$work/boot.original.raw" || exit 1
	awk -v keep_mount=1 -f "$SVPN_LIBRARY_DIR/dhcp-mount.awk" "$work/boot.original.raw" > "$work/boot.original" || exit 1
	awk -f "$SVPN_LIBRARY_DIR/dhcp-mount.awk" "$work/boot.original" > "$work/boot.original.clean" || exit 1
	# preserve a mount that existed before this transaction
	cmp -s "$work/boot.original" "$work/boot.original.clean" || exit 0
	cp "$path" "$work/boot.source" && chmod 600 "$work/boot.source" || exit 1
	svpn_uci_export "$work/boot.source" > "$work/boot.export.raw" || exit 1
	awk -v keep_mount=1 -f "$SVPN_LIBRARY_DIR/dhcp-mount.awk" "$work/boot.export.raw" > "$work/boot.export" || exit 1
	awk -f "$SVPN_LIBRARY_DIR/dhcp-mount.awk" "$work/boot.export" > "$work/boot.clean" || exit 1
	cmp -s "$work/boot.export" "$work/boot.clean" && exit 0
	svpn_uci_export "$work/boot.clean" > "$work/boot.checked.raw" || exit 1
	awk -v keep_mount=1 -f "$SVPN_LIBRARY_DIR/dhcp-mount.awk" "$work/boot.checked.raw" > "$work/boot.checked" || exit 1
	cmp -s "$work/boot.clean" "$work/boot.checked" || exit 1
	mode=$(stat -c '%a' "$path") || exit 1
	stage=$(mktemp "$SVPN_CONFIG_DIR/.selective-vpn.XXXXXXXX") || exit 1
	trap 'rm -f -- "$stage"' EXIT
	cat "$work/boot.clean" > "$stage" && chmod "$mode" "$stage" && sync || exit 1
	svpn_uci_clean dhcp && svpn_config_file "$path" && cmp -s "$path" "$work/boot.source" || exit 1
	mv -f -- "$stage" "$path" && sync
)
