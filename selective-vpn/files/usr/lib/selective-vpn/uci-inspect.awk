# input must be a canonical uci -N export
function fail() { bad = 1; exit 1 }
function consume(text,    i, ch, quote, escaped, token, started, n, a, key, value) {
	for (i = 1; i <= length(text); i++) {
		ch = substr(text, i, 1)
		if (escaped) { token = token ch; escaped = 0; started = 1 }
		else if (quote == "'") {
			if (ch == "'") quote = ""
			else token = token ch
		} else if (ch == "\\") { escaped = 1; started = 1 }
		else if (ch == "'") { quote = ch; started = 1 }
		else if (ch ~ /[ \t\n]/) {
			if (started) a[++n] = token
			token = ""; started = 0
		} else { token = token ch; started = 1 }
	}
	if (quote != "" || escaped) fail()
	if (!n) return
	if (a[1] == "package" && n == 2) return
	if (a[1] == "config" && (n == 2 || n == 3)) {
		if (++sections > 256 || a[2] !~ /^[a-zA-Z0-9_-]+$/) fail()
		value = (n == 3 ? a[3] : "-")
		if (value !~ /^[a-zA-Z0-9_-]+$/) fail()
		if (n == 3 && names[value]++) fail()
		print "S\t" sections "\t" a[2] "\t" value
		return
	}
	if (!sections || n != 3 || a[1] !~ /^(option|list)$/) fail()
	key = a[2]
	if (key !~ /^[a-zA-Z0-9_]+$/) fail()
	# omit unrelated values, including credentials
	if (package == "network") keep = key ~ /^(proto|device|ifname|ipaddr|netmask|gateway|defaultroute)$/
	else if (package == "firewall") keep = key ~ /^(name|network|device|subnet|input|output|forward|masq|masq_src|masq_dest|family|enabled|src|dest|target|proto|dest_port)$/
	else if (package == "openvpn") keep = key ~ /^(config|dev|dev_type|enabled|enable|up|down|route_up|route_pre_down|ipchange|script_security)$/
	else if (package == "dhcp") keep = key ~ /^(name|ip|leasename|leasefile|port|interface|notinterface|listen_address|dhcp_option|dhcp_option_force|ignore|disabled)$/
	else if (package == "pbr") keep = key ~ /^(enabled|resolver_set|resolver_instance|supported_interface|ignored_interface|ipv6_enabled|netifd_enabled|name|interface|chain|proto|src_addr|src_port|dest_addr|dest_port|dest_dns)$/
	else if (package == "selective-vpn") keep = key ~ /^(enabled|mode|selection|networks|devices|console|browser|fallback|custom|ipv6_acknowledged|rules|address|proto|dest_port|destinations|preset)$/
	else fail()
	if (!keep) return
	value = a[3]
	if (length(value) > 4096 || value ~ /[\t\r\n]/) fail()
	if (a[1] == "option" && seen[sections, key]++) fail()
	print "V\t" sections "\t" key "\t" value
}
{
	buffer = buffer $0 "\n"
	for (pos = 1; pos <= length($0); pos++) {
		ch = substr($0, pos, 1)
		if (!quoted && ch == "\\") { pos++; continue }
		if (ch == "'") quoted = !quoted
	}
	if (!quoted) { consume(buffer); buffer = "" }
}
END { if (bad || quoted || buffer != "") exit 1 }
