#!/bin/sh

svpn_rule_ports() (
	[ "$#" -eq 1 ] && svpn_valid_size "$1" "$SVPN_MAX_LIST_BYTES" || exit 1
	set -f
	set -- $1
	[ "$#" -le "$SVPN_MAX_LIST_ITEMS" ] || exit 1
	result=''
	for port do
		case "$port" in
			*-*) first=${port%%-*}; last=${port#*-} ;;
			*) first=$port; last=$port ;;
		esac
		svpn_valid_uint "$first" 65535 && svpn_valid_uint "$last" 65535 &&
			[ "$first" -gt 0 ] && [ "$first" -le "$last" ] || exit 1
		result="$result$port
"
	done
	printf '%s' "$result" | LC_ALL=C sort -u
)

svpn_rules_prepare() (
	[ "$#" -eq 2 ] && svpn_private_directory "$1" && svpn_private_directory "$2" || exit 1
	work=$1 network=$2
	svpn_config_file "$SVPN_CONFIG_DIR/selective-vpn" && svpn_uci_clean selective-vpn || exit 1
	cp "$SVPN_CONFIG_DIR/selective-vpn" "$work/app.source" || exit 1
	svpn_uci_export "$work/app.source" > "$work/app.export" || exit 1
	awk -v package=selective-vpn -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/app.export" > "$work/app.table" || exit 1
	type=rule
	[ "${svpn_rules:-}" != active ] || type=active_rule
	awk -F '\t' -v type="$type" '$1=="S" && $3==type {
		name=$4
		if(type=="active_rule") sub(/^svpn_rule_/,"",name)
		if(name !~ /^[a-zA-Z_][a-zA-Z0-9_]*$/ || length(name)>40 || ++count>24) exit 1
		if(name=="global") global++
		print name "\t" $4
	} END { if(global!=1) exit 1 }' "$work/app.table" > "$work/rows" || exit 1
	mkdir -m 700 "$work/rules" || exit 1
	: > "$work/devices"
	: > "$work/destinations"
	tab=$(printf '\t')
	while IFS="$tab" read -r name section; do
		row=$work/rules/$name
		mkdir -m 700 "$row" || exit 1
		for key in address proto dest_port destinations; do
			awk -F '\t' -v name="$section" -v key="$key" '
				$1=="S" && $4==name { s=$2 }
				$1=="V" && $2==s && $3==key { print $4 }' "$work/app.table" > "$row/$key.raw" || exit 1
		done
		address=$(cat "$row/address.raw") || exit 1
		if [ "$name" = global ]; then
			[ -z "$address" ] || exit 1
		else
			svpn_valid_ipv4 "$address" || exit 1
			! grep -qxF "$address" "$work/devices" || { svpn_state_error 'A device can only have one routing rule.'; exit 1; }
			printf '%s\n' "$address" >> "$work/devices"
			printf '%s\n' "$address" > "$row/sources"
		fi
		printf '%s\n' "$address" > "$row/address"
		proto=$(svpn_normalize_list identifier "$(cat "$row/proto.raw")") || exit 1
		[ -n "$proto" ] || proto='tcp udp'
		for value in $proto; do case "$value" in tcp|udp) ;; *) exit 1 ;; esac; done
		printf '%s\n' "$proto" | tr '\n' ' ' > "$row/proto"
		ports=$(svpn_rule_ports "$(cat "$row/dest_port.raw")") || exit 1
		printf '%s' "$ports" | tr '\n' ' ' > "$row/dest_port"
		destinations=$(svpn_policy_destinations "$(cat "$row/destinations.raw")") || exit 1
		printf '%s\n' "$destinations" > "$row/destinations"
		printf '%s\n' "$destinations" >> "$work/destinations"
		{
			printf "config active_rule 'svpn_rule_%s'\n" "$name"
			[ -z "$address" ] || printf "\toption address '%s'\n" "$address"
			printf "\toption proto '%s'\n\toption dest_port '%s'\n" "$(cat "$row/proto")" "$(cat "$row/dest_port")"
			for value in $destinations; do printf "\tlist destinations '%s'\n" "$value"; done
		} > "$row/active"
	done < "$work/rows"
	LC_ALL=C awk -v mode=scope -v scope=devices -f "$SVPN_LIBRARY_DIR/policy-check.awk" \
		"$work/devices" "$network/lan_subnets" "$network/live" || exit 1
	LC_ALL=C awk -f "$SVPN_LIBRARY_DIR/source-partition.awk" "$work/devices" "$network/lan_subnets" |
		LC_ALL=C sort -u > "$work/rules/global/sources" || exit 1
	for row in "$work/rules/"*; do
		sources=$(tr '\n' ' ' < "$row/sources") || exit 1
		svpn_valid_size "$sources" "$SVPN_MAX_LIST_BYTES" || { svpn_state_error 'The Global source partition is too large.'; exit 1; }
	done
	svpn_normalize_list destination "$(cat "$work/destinations")" > "$work/all.destinations" || exit 1
	mv "$work/all.destinations" "$work/destinations" || exit 1
)

svpn_rules_policies() (
	[ "$#" -eq 2 ] || exit 1
	work=$1 interface=$2
	for row in "$work/rules/"*; do
		name=${row##*/}
		sources=$(tr '\n' ' ' < "$row/sources") && dest=$(tr '\n' ' ' < "$row/destinations") || exit 1
		[ -n "$sources" ] && [ -n "$(cat "$row/destinations")" ] || continue
		proto=$(cat "$row/proto") && ports=$(cat "$row/dest_port") || exit 1
		target=pbr.svpn_route_$name
		svpn_resource_read section "$target" "$work/current" "$work" || exit 1
		if [ "$(head -n 1 "$work/current")" = present ]; then
			confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
			key=$(svpn_tx_key section "$target") || exit 1
			svpn_private_file "$tx/manifest/$key/applied" && cmp -s "$tx/manifest/$key/applied" "$work/current" || exit 1
		fi
		svpn_policy_section "svpn_route_$name" "Selective VPN: $name" "$interface" "${sources% }" "${dest% }" "${proto% }" "$ports" > "$work/fragment" || exit 1
		svpn_policy_resource "$work" section "$target" present < "$work/fragment" || exit 1
	done
	[ -e "$SVPN_PRIVATE_DIR/confirmed" ] || exit 0
	confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
	for record in "$tx/manifest/"*; do
		[ -e "$record" ] || continue
		kind=$(svpn_state_read "$record/kind") && target=$(svpn_state_read "$record/target") || exit 1
		case "$kind:$target" in section:pbr.svpn_route_*) ;; *) continue ;; esac
		[ ! -e "$work/resources/section.$target" ] || continue
		svpn_policy_resource "$work" section "$target" missing < /dev/null || exit 1
	done
)
