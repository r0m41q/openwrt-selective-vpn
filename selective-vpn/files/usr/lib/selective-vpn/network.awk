BEGIN { FS = "\t"; OFS = "\t" }
function fail(message) { bad = 1; print message > "/dev/stderr"; exit 1 }
function id(value) { return value ~ /^[a-zA-Z_][a-zA-Z0-9_]*$/ && length(value) <= 63 }
function ip(value,    a, n, i) {
	n = split(value, a, ".")
	if (n != 4) return -1
	for (i = 1; i <= 4; i++) if (a[i] !~ /^(0|[1-9][0-9]*)$/ || a[i] + 0 > 255) return -1
	return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4]
}
function host(value,    a, n, i) {
	if (length(value) > 253 || value !~ /^[a-zA-Z0-9.-]+$/) return 0
	n = split(value, a, ".")
	if (a[n] !~ /[a-zA-Z]/) return 0
	for (i = 1; i <= n; i++) if (length(a[i]) < 1 || length(a[i]) > 63 || a[i] ~ /^-|-$/) return 0
	return 1
}
function power(bits,    value) { value = 1; while (bits-- > 0) value *= 2; return value }
function dotted(value,    d, c, b, a) {
	d = value % 256; value = int(value / 256)
	c = value % 256; value = int(value / 256)
	b = value % 256; a = int(value / 256)
	return a "." b "." c "." d
}
function prefix(value, bits) { return int(value / power(32 - bits)) * power(32 - bits) }
function overlaps(a, abits, b, bbits,    bits) {
	bits = (abits < bbits ? abits : bbits)
	return prefix(a, bits) == prefix(b, bits)
}
function words(text, value,    a, n, i) {
	n = split(text, a, / +/)
	for (i = 1; i <= n; i++) if (a[i] == value) return 1
	return 0
}
function option(p, s, key, fallback) { return ((p SUBSEP s SUBSEP key) in v ? v[p,s,key] : fallback) }
function output(name, value) { print value > (out "/" name); close(out "/" name) }
function resource(target, value) { printf "%s", value > (out "/resources/" target); close(out "/resources/" target) }
function field(key, value) { return "\toption " key " '" value "'\n" }
function list(key, value) { return "\tlist " key " '" value "'\n" }
function section(type, name) { return "config " type " '" name "'\n" }
function device_matches(text, device,    a, n, i, pattern) {
	if (device == "" || device == "-") return 0
	n = split(text, a, / +/)
	for (i = 1; i <= n; i++) {
		pattern = a[i]
		if (pattern == device) return 1
		if (pattern ~ /\+$/ && substr(device,1,length(pattern)-1) == substr(pattern,1,length(pattern)-1)) return 1
	}
	return 0
}
function zone_for(net,    s, z, found) {
	for (s = 1; s <= count["firewall"]; s++) {
		if (option("firewall",s,"enabled","1") !~ /^[01]$/) fail("Firewall enabled values must be 0 or 1.")
		if (type["firewall",s] != "zone" || option("firewall",s,"enabled","1") == "0") continue
		if (words(v["firewall",s,"network"], net) || device_matches(v["firewall",s,"device"],dev[net])) {
			z = v["firewall",s,"name"]
			if (found != "") fail("A network belongs to more than one firewall zone.")
			found = z
		}
	}
	if (live_zone[net] != "-" && live_zone[net] != "") {
		if (found != "" && found != live_zone[net]) fail("Live and saved firewall membership disagree.")
		found = live_zone[net]
	}
	return found
}
function selected_address(value,    i, n) {
	n = ip(value)
	if (n < 0) return 0
	for (i = 1; i <= addresses; i++) if (n == addr[i]) return 0
	for (i = 1; i <= addresses; i++) {
		if (selected[aname[i]] && prefix(n, mask[i]) == prefix(addr[i], mask[i])) {
			if (n == prefix(addr[i], mask[i]) || n == prefix(addr[i], mask[i]) + power(32-mask[i]) - 1) return 0
			return 1
		}
	}
	return 0
}
function lease(address, name,    key) {
	name = tolower(name)
	if (ip(address) < 0 || !host(name)) return
	key = name SUBSEP address
	if (!lease_seen[key]++) {
		lease_count[name]++
		lease_ip[name] = address
		if (selected_address(address)) print address, name > (out "/leases")
	}
}
FILENAME ~ /\.table$/ {
	p = FILENAME; sub(/^.*\//, "", p); sub(/\.table$/, "", p)
	if ($1 == "S") { count[p]++; type[p,$2] = $3; name[p,$2] = $4 }
	else if ($1 == "V") {
		key = p SUBSEP $2 SUBSEP $3
		if (key in v) v[key] = v[key] " " $4
		else v[key] = $4
	} else fail("Invalid configuration inventory.")
	next
}
FILENAME ~ /\/live$/ {
	if ($1 == "I") {
		if (seen_live[$2]++) fail("Duplicate live network.")
		up[$2] = $3; dev[$2] = $4; live_zone[$2] = $5
	} else if ($1 == "A") {
		addresses++; aname[addresses] = $2; addr[addresses] = ip($3); mask[addresses] = $4 + 0
		if (addr[addresses] < 0 || $4 !~ /^[0-9]+$/ || mask[addresses] > 32) fail("Invalid live IPv4 address.")
	}
	next
}
FILENAME ~ /\/leases.raw$/ { lease_address[++leases] = $1; lease_name[leases] = $2; next }
FILENAME ~ /\/vpn.summary$/ {
	split($0, pair, "="); summary[pair[1]] = pair[2]; next
}
END {
	if (bad) exit 1
	for (s = 1; s <= count["network"]; s++) {
		if (type["network",s] == "interface") {
			n = name["network",s]
			if (n == "-" || !id(n) || length(n) > 15) fail("A network needs a supported explicit interface name.")
			net_section[n] = s
		}
	}
	for (s = 1; s <= count["firewall"]; s++) {
		if (type["firewall",s] != "zone" || option("firewall",s,"enabled","1") == "0") continue
		z = v["firewall",s,"name"]
		if (!id(z) || zones[z]++) fail("Firewall zones need unique supported names.")
		zone_section[z] = s
		num = split(v["firewall",s,"network"], items, / +/)
		for (i = 1; i <= num; i++) if (items[i] != "" && !id(items[i])) fail("Firewall network matches require explicit interface names.")
		if (v["firewall",s,"device"] ~ /!/) fail("Inverted firewall device matches require manual review.")
		if (v["firewall",s,"subnet"] != "") fail("Subnet-based firewall zones require manual review.")
	}
	networks_count = split(networks, requested, /[ \n]+/)
	if (networks == "") {
		if (!("lan" in zone_section)) fail("Select the LAN networks explicitly.")
		s = zone_section["lan"]
		if (v["firewall",s,"input"] != "ACCEPT" || option("firewall",s,"masq","0") != "0") fail("Select the LAN networks explicitly.")
		networks_count = split(v["firewall",s,"network"], requested, / +/)
	}
	if (networks_count < 1 || networks_count > 64) fail("No eligible LAN networks were selected.")
	for (i = 1; i <= networks_count; i++) {
		n = requested[i]; s = net_section[n]; z = zone_for(n)
		if (!id(n) || !s || selected[n]++ || up[n] != "true" || dev[n] == "-" || z == "") fail("A selected LAN network is unavailable or ambiguous.")
		if (v["network",s,"proto"] != "static" || option("firewall",zone_section[z],"masq","0") != "0") fail("Select local static LAN networks without masquerading.")
		if (!zone_section[z]) fail("A LAN firewall zone is missing.")
		lan_zones[z] = 1
		print n > (out "/lan_networks")
	}
	for (i = 1; i <= addresses; i++) {
		if (!selected[aname[i]]) continue
		if (mask[i] < 1 || mask[i] > 30 || addr[i] < 16777216 || addr[i] >= 3758096384 || int(addr[i] / 16777216) == 127) fail("The LAN IPv4 subnet is unsupported.")
		for (j = 1; j <= addresses; j++) {
			if (aname[i] != aname[j] && overlaps(addr[i],mask[i],addr[j],mask[j])) fail("LAN address space overlaps another network.")
		}
		n = dotted(prefix(addr[i],mask[i])) "/" mask[i]
		if (!subnets[n]++) { print n > (out "/lan_subnets"); subnet_count++ }
		with_address[aname[i]] = 1
	}
	for (i = 1; i <= networks_count; i++) if (!with_address[requested[i]]) fail("A selected LAN network has no usable IPv4 address.")
	for (s = 1; s <= count["dhcp"]; s++) {
		if (type["dhcp",s] == "host") lease(v["dhcp",s,"ip"],v["dhcp",s,"name"])
		if (type["dhcp",s] == "dnsmasq" && v["dhcp",s,"leasefile"] != "" && v["dhcp",s,"leasefile"] != leasefile) fail("Custom DHCP lease files are not supported yet.")
	}
	for (i = 1; i <= leases; i++) lease(lease_address[i],lease_name[i])
	if (devices == "") {
		output("scope", "lan")
		for (n in subnets) print n > (out "/sources")
	} else {
		output("scope", "devices")
		num = split(devices, items, /[ \n]+/)
		for (i = 1; i <= num; i++) {
			n = items[i]
			if (ip(n) < 0) {
				if (!host(n) || lease_count[n] != 1) fail("A device hostname has no unique current DHCP address.")
				n = lease_ip[n]
			}
			if (!selected_address(n)) fail("A selected device is outside the LAN or is a router address.")
			if (!sources[n]++) print n > (out "/sources")
		}
	}
	# static tunnel addresses can create connected routes despite route-nopull
	if (summary["ifconfig_local"] != "") {
		a = ip(summary["ifconfig_local"]); b = ip(summary["ifconfig_peer"])
		bits = 32
		if (summary["topology"] == "subnet") {
			for (bits = 0; bits <= 32; bits++) if (b == 4294967296 - power(32-bits)) break
			if (bits < 8 || bits > 32) fail("The static VPN subnet mask is unsafe.")
		} else if (summary["topology"] == "net30") bits = 30
		for (i = 1; i <= addresses; i++) {
			if (dev[aname[i]] == tun) continue
			if (overlaps(a,bits,addr[i],mask[i]) || (summary["topology"] != "subnet" && overlaps(b,32,addr[i],mask[i]))) fail("Static VPN addressing overlaps a local network.")
		}
	}
	logical = "svpn_vpn"
	for (n in net_section) {
		s = net_section[n]
		if (dev[n] != tun && v["network",s,"device"] != tun && v["network",s,"ifname"] != tun) continue
		if (mode == "managed" && n != logical) fail("The VPN device is already used by another network.")
		if (v["network",s,"proto"] != "none") fail("The VPN logical interface must use proto none.")
		if (existing_logical != "" && existing_logical != n) fail("The VPN device has multiple logical interfaces.")
		existing_logical = n
	}
	if (mode == "external" && existing_logical != "") logical = existing_logical
	if (logical == "svpn_vpn") resource("network.svpn_vpn", section("interface",logical) field("proto","none") field("auto","1"))
	if (mode == "managed") resource("openvpn.svpn_client", section("openvpn","svpn_client") field("enabled","1") field("config",profile) field("dev",tun) field("dev_type","tun"))
	vpn_zone = zone_for(logical)
	for (s = 1; s <= count["firewall"]; s++) {
		if (type["firewall",s] != "zone" || option("firewall",s,"enabled","1") == "0") continue
		z = v["firewall",s,"name"]
		if (!device_matches(v["firewall",s,"device"],tun)) continue
		if (vpn_zone != "" && vpn_zone != z) fail("The VPN device belongs to conflicting firewall zones.")
		vpn_zone = z
	}
	if (vpn_zone == "") {
		vpn_zone = "svpn_vpn"
		if ((vpn_zone in zone_section) && !(owned_zone && name["firewall",zone_section[vpn_zone]] == "svpn_zone")) fail("The reserved VPN zone name is already used.")
		resource("firewall.svpn_zone", section("zone","svpn_zone") field("name",vpn_zone) list("network",logical) field("input","REJECT") field("output","ACCEPT") field("forward","REJECT") field("family","ipv4") field("masq","1") field("mtu_fix","1"))
	} else {
		s = zone_section[vpn_zone]
		if (mode == "managed" && vpn_zone != "svpn_vpn") fail("The imported VPN device already matches an external firewall zone.")
		if (!s || (vpn_zone in lan_zones) || v["firewall",s,"input"] !~ /^(REJECT|DROP)$/ || v["firewall",s,"output"] != "ACCEPT" || v["firewall",s,"forward"] !~ /^(REJECT|DROP)$/ || v["firewall",s,"masq"] != "1" || v["firewall",s,"masq_src"] != "" || v["firewall",s,"masq_dest"] != "" || v["firewall",s,"family"] ~ /6/) fail("The existing VPN firewall zone needs manual review.")
		if (name["firewall",s] == "svpn_zone") resource("firewall.svpn_zone", section("zone","svpn_zone") field("name",vpn_zone) list("network",logical) field("input","REJECT") field("output","ACCEPT") field("forward","REJECT") field("family","ipv4") field("masq","1") field("mtu_fix","1"))
	}
	for (z in lan_zones) {
		print z > (out "/lan_zones")
		found = 0; found_section = 0
		for (s = 1; s <= count["firewall"]; s++) {
			if (type["firewall",s] == "rule" && option("firewall",s,"enabled","1") != "0" && (v["firewall",s,"src"] == z || v["firewall",s,"src"] == "*") && (v["firewall",s,"dest"] == vpn_zone || v["firewall",s,"dest"] == "*") && v["firewall",s,"target"] ~ /^(DROP|REJECT)$/) fail("An existing firewall rule may block LAN to VPN traffic.")
			if (type["firewall",s] == "forwarding" && option("firewall",s,"enabled","1") != "0" && v["firewall",s,"src"] == z && v["firewall",s,"dest"] == vpn_zone) { found++; found_section=s }
		}
		if (found > 1) fail("Duplicate LAN to VPN forwarding exists.")
		if (!found || name["firewall",found_section] == "svpn_fwd_" z) {
			if (length(z) > 40) fail("The LAN zone name is too long.")
			n = "svpn_fwd_" z
			resource("firewall." n, section("forwarding",n) field("src",z) field("dest",vpn_zone) field("family","ipv4"))
		}
	}
	output("interface",logical); output("device",tun); output("zone",vpn_zone)
	output("vpn_mode",mode); output("client",client)
}
