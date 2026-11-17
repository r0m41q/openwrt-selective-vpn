function field(key, choices, initial) {
	order[++count] = key
	allowed[key] = choices
	value[key] = initial
}
# one entry per generated policy, named after its rule and preset
function policies(group, choices) {
	order[++count] = group ".*"
	allowed[group ".*"] = choices
}
function valid(choices, text) {
	if (choices == "number") return (text == "null" || (text ~ /^(0|[1-9][0-9]*)$/ && length(text) <= 15))
	if (choices == "bool") return (text ~ /^(true|false|null)$/)
	if (choices == "interface") return (text == "" || (text ~ /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/ && length(text) <= 15))
	if (choices == "tokens") return (length(text) <= 4096 && text !~ /[^a-z0-9 .\/-]/)
	return (text ~ /^[a-z_]+$/ && index(" " choices " ", " " text " ") > 0)
}
BEGIN {
	FS = "\t"
	field("collection.state", "complete partial busy unavailable", "unavailable")
	field("configuration.enabled", "bool", "null")
	field("configuration.rules", "number", "null")
	field("configuration.pending_uci", "present absent unknown", "unknown")
	field("configuration.owned_settings", "match changed unknown", "unknown")
	field("recovery.state", "none preparing armed applying applied awaiting_confirmation confirmed recovering runtime_recovery conflict rolled_back unknown", "unknown")
	field("recovery.seconds_remaining", "number", "null")
	field("recovery.supervisor", "running stopped unknown", "unknown")
	split("timeout ubus jsonfilter uci nft ip_full ss dnsmasq openvpn fw4 pbr logread", dependencies, " ")
	for (i = 1; i <= 12; i++) field("dependencies." dependencies[i], "available missing unknown", "unknown")
	field("vpn.process", "running stopped unverified unknown", "unknown")
	field("vpn.ipv4", "usable missing invalid unknown", "unknown")
	field("vpn.tunnel", "ready not_ready unknown", "unknown")
	field("vpn.logical_interface", "attached detached unknown", "unknown")
	field("vpn.replaced_client", "none stopped running unknown", "unknown")
	field("routing.main_ipv4_default", "present missing unknown", "unknown")
	field("routing.ipv6_default", "present missing unknown", "unknown")
	field("routing.vpn_default", "present missing unknown", "unknown")
	field("routing.mark_rule", "present missing unknown", "unknown")
	field("routing.activation_baseline", "unchanged changed stale unknown", "unknown")
	field("pbr.version", "supported unsupported unknown", "unknown")
	field("pbr.service", "running stopped unknown", "unknown")
	field("pbr.errors", "present absent unknown", "unknown")
	field("pbr.policy_configuration", "match changed unknown", "unknown")
	policies("policies", "present absent unknown")
	policies("packets", "number")
	policies("bytes", "number")
	field("dns.nftset_capability", "supported unsupported unknown", "unknown")
	field("dns.integration", "ready not_ready not_required unknown", "unknown")
	field("dns.sets", "number", "null")
	field("dns.population", "nonempty empty unknown not_required", "unknown")
	field("dns.resolution", "not_probed", "not_probed")
	field("firewall.candidate", "valid invalid unknown", "unknown")
	field("firewall.source", "saved_configuration", "saved_configuration")
	field("firewall.zone", "found missing ambiguous unknown", "unknown")
	field("firewall.masquerading", "bool", "null")
	field("firewall.input_restricted", "bool", "null")
	field("firewall.forward_restricted", "bool", "null")
	field("evidence.tunnel", "observed unverified", "unverified")
	field("evidence.policy_rules", "observed unverified", "unverified")
	field("evidence.policy_matches", "observed unverified", "unverified")
	field("evidence.vpn_egress", "unverified", "unverified")
	field("evidence.device_authentication", "unverified", "unverified")
	field("evidence.game_stream", "unverified", "unverified")
	field("evidence.exit_ip", "unknown", "unknown")
	field("evidence.exit_country", "unknown", "unknown")
	field("logs.state", "summarized unavailable not_requested", "not_requested")
	field("logs.scope", "all_openvpn_instances", "all_openvpn_instances")
	field("logs.authentication_failure", "number", "null")
	field("logs.tls_failure", "number", "null")
	field("logs.connection_failure", "number", "null")
	field("logs.restart", "number", "null")
	if (report == "status") {
		field("details.interface", "interface", "")
		field("details.addresses", "tokens", "")
		policies("sources", "tokens")
		policies("destinations", "tokens")
		policies("protocols", "tokens")
		policies("ports", "tokens")
	}
}
{
	if (NF != 2) { bad = 1; next }
	if ($1 in allowed && $1 !~ /\.\*$/) {
		if (!valid(allowed[$1], $2)) { bad = 1; next }
		value[$1] = $2
		next
	}
	group = $1; sub(/\..*$/, "", group)
	name = substr($1, length(group) + 2)
	if (!((group ".*") in allowed) || name !~ /^[a-zA-Z_][a-zA-Z0-9_]*$/ || length(name) > 120 ||
		!valid(allowed[group ".*"], $2) || ++dynamic > 1024) { bad = 1; next }
	if (!((group, name) in extra)) names[group, ++listed[group]] = name
	extra[group, name] = $2
}
END {
	if (bad || report !~ /^(status|doctor)$/) exit 1
	printf "{\"schema\":2,\"report\":\"%s\"", report
	group = ""
	for (i = 1; i <= count; i++) {
		key = order[i]
		split(key, parts, ".")
		if (parts[1] != group) {
			if (group != "") printf "}"
			printf ",\"%s\":{", parts[1]
			group = parts[1]; separator = ""
		}
		if (parts[2] == "*") {
			for (j = 1; j <= listed[group]; j++) {
				name = names[group, j]
				printf "%s\"%s\":", separator, name
				if (allowed[key] == "number") printf "%s", extra[group, name]
				else printf "\"%s\"", extra[group, name]
				separator = ","
			}
			continue
		}
		printf "%s\"%s\":", separator, parts[2]
		if (allowed[key] == "bool" || allowed[key] == "number") printf "%s", value[key]
		else printf "\"%s\"", value[key]
		separator = ","
	}
	printf "},\"limitations\":[\"ipv4_only\",\"client_dns_must_use_router\",\"encrypted_dns_and_cached_answers_may_bypass_sets\",\"domain_equivalence_needs_validation\",\"counters_do_not_prove_vpn_egress_or_authentication\",\"logs_are_recent_historical_signals\",\"no_external_lookup_performed\"],\"privacy\":\"allowlisted_fields_and_log_categories_only\"}\n"
}
