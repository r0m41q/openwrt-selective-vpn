BEGIN { FS = "\t" }
function fail(message) { bad = 1; print message > "/dev/stderr"; exit 1 }
function words(text, word,    a, n, i) {
	n = split(text,a,/ +/)
	for (i = 1; i <= n; i++) if (a[i] == word) return 1
	return 0
}
FILENAME ~ /dhcp\.table$/ {
	if ($1 == "S") { type[$2] = $3; name[$2] = $4; sections++ }
	if ($1 == "V") {
		key = $2 SUBSEP $3
		if (key in v) v[key] = v[key] " " $4
		else v[key] = $4
	}
	next
}
FILENAME ~ /\/routers$/ { routers[$1] = $2; networks[$2] = 1; next }
FILENAME ~ /\/listeners$/ {
	# ss -H -4 -lnptu: protocol, state, queues, local endpoint, peer, process
	line = $0; sub(/^[ \t]+/, "", line); split(line, fields, /[ \t]+/)
	protocol = fields[1]; state = fields[2]; endpoint = fields[5]
	if (protocol !~ /^(udp|tcp)$/ || endpoint !~ /:53$/) next
	if (protocol == "tcp" && state != "LISTEN") next
	if (protocol == "udp" && state != "UNCONN") next
	if ($0 !~ /users:\(\("dnsmasq",pid=[0-9]+,fd=[0-9]+\)\)/) fail("Another service owns a DNS listener. Check the DNS forwarding layout.")
	if (!index($0, "pid=" expected_pid ",fd=")) fail("A DNS listener does not belong to the OpenWrt dnsmasq instance.")
	address = endpoint; sub(/:53$/, "", address)
	if (address == "0.0.0.0" || address == "*") wildcard[protocol] = 1
	else listening[protocol,address] = 1
	listener_count++
	next
}
END {
	if (bad) exit 1
	for (s = 1; s <= sections; s++) if (type[s] == "dnsmasq") { instances++; instance = s }
	if (instances != 1) fail("Domain policies currently require one dnsmasq instance.")
	if (v[instance,"disabled"] != "" && v[instance,"disabled"] != "0") fail("The dnsmasq instance is disabled.")
	if (v[instance,"port"] != "" && v[instance,"port"] != "53") fail("Domain policies require dnsmasq to listen on port 53.")
	if (resolver_instance != "" && resolver_instance != "*" && resolver_instance != "0" && resolver_instance != name[instance]) fail("PBR does not select the LAN dnsmasq instance.")
	for (address in routers) {
		net = routers[address]
		if (v[instance,"interface"] != "" && !words(v[instance,"interface"],net)) fail("dnsmasq does not serve every selected LAN network.")
		if (words(v[instance,"notinterface"],net)) fail("dnsmasq excludes a selected LAN network.")
		if (v[instance,"listen_address"] != "" && !words(v[instance,"listen_address"],address) && !words(v[instance,"listen_address"],"0.0.0.0")) fail("dnsmasq does not listen on every selected LAN address.")
		if ((!wildcard["udp"] && !listening["udp",address]) || (!wildcard["tcp"] && !listening["tcp",address])) fail("No dnsmasq UDP and TCP listeners were found for a selected LAN address.")
	}
	if (!listener_count) fail("No active dnsmasq DNS listener was found.")
	for (s = 1; s <= sections; s++) {
		if (type[s] != "dhcp" || v[s,"ignore"] == "1" || !networks[v[s,"interface"]]) continue
		for (kind = 1; kind <= 2; kind++) {
			key = (kind == 1 ? "dhcp_option" : "dhcp_option_force")
			num = split(v[s,key], options, / +/)
			for (i = 1; i <= num; i++) {
				if (options[i] !~ /^(6|option:dns-server),/) continue
				count = split(options[i], servers, ",")
				for (j = 2; j <= count; j++) if (!(servers[j] in routers) || routers[servers[j]] != v[s,"interface"]) fail("A LAN DHCP option advertises DNS outside its router addresses.")
			}
		}
	}
}
