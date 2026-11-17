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

svpn_rule_proto() (
	[ "$#" -eq 1 ] || exit 1
	proto=$(svpn_normalize_list identifier "$1") || exit 1
	[ -n "$proto" ] || proto='tcp udp'
	for value in $proto; do case "$value" in tcp|udp) ;; *) exit 1 ;; esac; done
	printf '%s\n' "$proto" | tr '\n' ' '
)

# print one field of a shipped preset, fail for unknown ids
svpn_preset_field() (
	[ "$#" -eq 2 ] && svpn_valid_identifier "$1" && svpn_valid_identifier "$2" || exit 1
	LC_ALL=C awk -v id="$1" -v key="$2" '
		$1 == "preset" { current = $2; if (current == id) found = 1; next }
		current == id && $1 == key { sub(/^[ \t]*[^ \t]+[ \t]*/, ""); print }
		END { exit !found }' "$SVPN_LIBRARY_DIR/presets"
)

# presets get the same checks as rule rows
svpn_preset_load() (
	[ "$#" -eq 2 ] && svpn_private_directory "$2" || exit 1
	case "$1" in ''|*__*|*[!a-z0-9_]*|[!a-z]*) exit 1 ;; esac
	label=$(svpn_preset_field "$1" label) || { svpn_state_error "Unknown routing preset: $1"; exit 1; }
	proto=$(svpn_preset_field "$1" proto) && proto=$(svpn_rule_proto "$proto") &&
		ports=$(svpn_preset_field "$1" dest_port) && ports=$(svpn_rule_ports "$ports") &&
		destinations=$(svpn_preset_field "$1" destinations) &&
		destinations=$(svpn_policy_destinations "$destinations") &&
		warning=$(svpn_preset_field "$1" warning) || exit 1
	[ -n "$label" ] && [ -n "$destinations" ] || exit 1
	case "$warning" in ''|static_console_addresses_may_be_outdated) ;; *) exit 1 ;; esac
	printf '%s\n' "$label" > "$2/label" && printf '%s' "$proto" > "$2/proto" &&
		printf '%s' "$ports" | tr '\n' ' ' > "$2/dest_port" &&
		printf '%s\n' "$destinations" > "$2/destinations" || exit 1
	if [ -n "$warning" ]; then printf '%s\n' "$warning"; fi > "$2/warning"
)

# destinations of one preset for the older console and browser switches
svpn_rules_preset() (
	[ "$#" -eq 2 ] || exit 1
	directory=$1/preset.$2
	mkdir -m 700 "$directory" && svpn_preset_load "$2" "$directory" &&
		cat "$directory/warning" >> "$1/warnings" || exit 1
	destinations=$(tr '\n' ' ' < "$directory/destinations") || exit 1
	printf '%s\n' "${destinations% }"
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
		# a double underscore separates the rule from its preset in policy names
		if(name !~ /^[a-zA-Z_][a-zA-Z0-9_]*$/ || name ~ /__/ || length(name)>40 || ++count>24) exit 1
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
		for key in address proto dest_port destinations preset; do
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
		svpn_rule_proto "$(cat "$row/proto.raw")" > "$row/proto" || exit 1
		ports=$(svpn_rule_ports "$(cat "$row/dest_port.raw")") || exit 1
		printf '%s' "$ports" | tr '\n' ' ' > "$row/dest_port"
		destinations=$(svpn_policy_destinations "$(cat "$row/destinations.raw")") || exit 1
		printf '%s\n' "$destinations" > "$row/destinations"
		printf '%s\n' "$destinations" >> "$work/destinations"
		presets=$(svpn_normalize_list identifier "$(cat "$row/preset.raw")") || exit 1
		mkdir -m 700 "$row/presets" || exit 1
		for preset in $presets; do
			mkdir -m 700 "$row/presets/$preset" && svpn_preset_load "$preset" "$row/presets/$preset" || exit 1
			cat "$row/presets/$preset/destinations" >> "$work/destinations" &&
				cat "$row/presets/$preset/warning" >> "$work/warnings" || exit 1
		done
		{
			printf "config active_rule 'svpn_rule_%s'\n" "$name"
			[ -z "$address" ] || printf "\toption address '%s'\n" "$address"
			printf "\toption proto '%s'\n\toption dest_port '%s'\n" "$(cat "$row/proto")" "$(cat "$row/dest_port")"
			for value in $destinations; do printf "\tlist destinations '%s'\n" "$value"; done
			for value in $presets; do printf "\tlist preset '%s'\n" "$value"; done
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

svpn_rules_policy() (
	[ "$#" -eq 5 ] || exit 1
	work=$1 interface=$2 name=$3 sources=$4 row=$5
	[ -n "$(cat "$row/destinations")" ] || exit 0
	dest=$(tr '\n' ' ' < "$row/destinations") && proto=$(cat "$row/proto") && ports=$(cat "$row/dest_port") || exit 1
	target=pbr.svpn_route_$name
	svpn_resource_read section "$target" "$work/current" "$work" || exit 1
	if [ "$(head -n 1 "$work/current")" = present ]; then
		confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
		key=$(svpn_tx_key section "$target") || exit 1
		svpn_private_file "$tx/manifest/$key/applied" && cmp -s "$tx/manifest/$key/applied" "$work/current" || exit 1
	fi
	case "$name" in *__*) label="${name%%__*} ${name#*__}" ;; *) label=$name ;; esac
	svpn_policy_section "svpn_route_$name" "Selective VPN: $label" "$interface" "$sources" "${dest% }" "${proto% }" "$ports" > "$work/fragment" || exit 1
	svpn_policy_resource "$work" section "$target" present < "$work/fragment"
)

# each preset keeps its own protocol and ports in a separate policy
svpn_rules_policies() (
	[ "$#" -eq 2 ] || exit 1
	work=$1 interface=$2
	for row in "$work/rules/"*; do
		name=${row##*/}
		sources=$(tr '\n' ' ' < "$row/sources") || exit 1
		[ -n "$sources" ] || continue
		svpn_rules_policy "$work" "$interface" "$name" "${sources% }" "$row" || exit 1
		for preset in "$row/presets/"*; do
			[ -d "$preset" ] || continue
			svpn_rules_policy "$work" "$interface" "${name}__${preset##*/}" "${sources% }" "$preset" || exit 1
		done
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
