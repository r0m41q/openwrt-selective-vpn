# modes: uci builds a profile from client options, check lists split tunnel
# problems, refs moves file references out so they can be inlined
function fail() { bad = 1; exit 1 }
function unquote(value) {
	if (value ~ /^".*"$/ || value ~ /^'.*'$/) return substr(value, 2, length(value) - 2)
	return value
}

mode == "uci" {
	if ($0 ~ /^config /) next
	if (!match($0, /^\t(option|list) [a-zA-Z0-9_]+ '/)) fail()
	split(substr($0, 2, RLENGTH - 2), head, " ")
	key = head[2]
	value = substr($0, RLENGTH)
	if (value !~ /^'.*'$/) fail()
	value = substr(value, 2, length(value) - 2)
	gsub(/'\\''/, "'", value)
	if (key ~ /^(enabled|enable|config)$/ || key ~ /^_/) next
	name = key
	gsub(/_/, "-", name)
	if (key ~ /^(client|tls_client|pull|nobind|persist_key|persist_tun|route_nopull|auth_nocache|mute_replay_warnings|remote_random|remote_random_hostname|disable_dco|block_outside_dns)$/) {
		if (value == "1") print name
		else if (value != "0") fail()
		next
	}
	if (value == "" || value ~ /[\r\n]/) fail()
	print name " " value
	next
}

{
	line = $0
	sub(/\r$/, "", line)
	clean = line
	sub(/^[ \t]+/, "", clean)
	if (block != "") {
		if (clean ~ "^</" block ">[ \t]*$") block = ""
		if (mode == "refs") print line
		next
	}
	count = split(clean, a, /[ \t]+/)
	if (a[count] == "") count--
	name = a[1]
	sub(/^--/, "", name)
	if (name ~ /^<[a-z][a-z0-9-]*>$/) {
		block = substr(name, 2, length(name) - 2)
		if (mode == "refs") print line
		next
	}
}

mode == "check" {
	if (name == "dev") file_dev = unquote(a[2])
	else if (name == "route-nopull") nopull = 1
	else if (name == "pull-filter" && unquote(a[2]) == "ignore" && unquote(a[3]) == "ifconfig-ipv6") ipv6 = 1
	else if (name ~ /^(redirect-gateway|redirect-private|route|route-ipv6|route-delay|route-metric|route-noexec)$/) routes = 1
	else if (name ~ /^(dhcp-option|dns|block-outside-dns)$/) dns = 1
	next
}

mode == "refs" {
	if (name ~ /^(ca|cert|key|tls-auth|tls-crypt|tls-crypt-v2)$/ && count >= 2 && unquote(a[2]) != "[inline]") {
		if (count > 3 || (count == 3 && (name != "tls-auth" || a[3] !~ /^[01]$/))) fail()
		printf "%s\t%s\t%s\n", name, unquote(a[2]), (count == 3 ? a[3] : "") > refs
		next
	}
	if (name == "auth-user-pass" && count == 2) {
		print unquote(a[2]) > credentials
		print "auth-user-pass"
		next
	}
	if (name == "key-direction") printf "1" > direction
	print line
	next
}

END {
	if (bad || block != "") exit 1
	if (mode == "refs") { printf "" > refs; printf "" > credentials; printf "" > direction }
	if (mode != "check") exit
	device = (dev != "" ? dev : file_dev)
	if (file_dev == "" || device != file_dev || device == "tun" || device ~ /^tap/ || device !~ /^[a-zA-Z][a-zA-Z0-9_.-]*$/ ||
		length(device) > 15 || (dev_type != "" && dev_type != "tun")) print "device\t"
	if (!nopull) print "route_nopull\t"
	if (!ipv6) print "ipv6_filter\t"
	if (routes) print "routes\t"
	if (dns) print "dns\t"
}
