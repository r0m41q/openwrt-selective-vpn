BEGIN { FS = "\t" }
function number(value,    a,n,i) {
	n = split(value,a,".")
	if (n != 4) return -1
	for (i = 1; i <= 4; i++) if (a[i] !~ /^[0-9]+$/ || a[i] > 255) return -1
	return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4]
}
function power(bits,    value) { value = 1; while (bits-- > 0) value *= 2; return value }
function ip_overlap(a,b,    aa,bb,x,y,bits) {
	split(a,aa,"/"); split(b,bb,"/")
	x = number(aa[1]); y = number(bb[1])
	if (x < 0 || y < 0) return -1
	if (aa[2] == "") aa[2] = 32
	if (bb[2] == "") bb[2] = 32
	if (aa[2] !~ /^[0-9]+$/ || bb[2] !~ /^[0-9]+$/ || aa[2] > 32 || bb[2] > 32) return -1
	bits = (aa[2] < bb[2] ? aa[2] : bb[2])
	return int(x / power(32-bits)) == int(y / power(32-bits))
}
function may_overlap(text, values,    a,n,i,j,result) {
	if (text == "") return 1
	n = split(text,a,/ +/)
	for (i = 1; i <= n; i++) for (j in values) {
		result = ip_overlap(a[i],j)
		# names and negated matches need runtime resolution
		if (result != 0) return 1
	}
	return 0
}
FILENAME ~ /pbr\.owned$/ { owned[$1]=1; next }
FILENAME ~ /pbr\.table$/ {
	if ($1 == "S") { type[$2] = $3; name[$2] = $4; sections++ }
	if ($1 == "V") {
		key = $2 SUBSEP $3
		if (key in v) v[key] = v[key] " " $4
		else v[key] = $4
	}
	next
}
FILENAME ~ /\/(sources|devices)$/ { sources[$1] = 1; next }
FILENAME ~ /\/lan_subnets$/ { eligible[$1] = 1; next }
FILENAME ~ /\/live$/ { if ($1 == "A") routers[$3] = 1; next }
FILENAME ~ /\/destinations$/ { destinations[$1] = 1; next }
END {
	if (mode == "scope") {
		for (source in sources) {
			if (scope == "lan") {
				if (!(source in eligible)) exit 1
			} else {
				if (source in routers) exit 1
				found = 0
				for (subnet in eligible) if (ip_overlap(source,subnet) == 1) {
					split(subnet, parts, "/")
					first = number(parts[1]); last = first + power(32-parts[2]) - 1
					if (number(source) != first && number(source) != last) found = 1
				}
				if (!found) exit 1
			}
		}
		exit
	}
	for (s = 1; s <= sections; s++) {
		if (v[s,"enabled"] == "0") continue
		if (name[s] in owned) continue
		if (type[s] == "dns_policy" && domains && may_overlap(v[s,"src_addr"],sources)) {
			print "An existing PBR DNS policy may bypass the integrated resolver." > "/dev/stderr"
			exit 1
		}
		if (type[s] != "policy" || (v[s,"chain"] != "" && v[s,"chain"] != "prerouting")) continue
		if (may_overlap(v[s,"src_addr"],sources) && may_overlap(v[s,"dest_addr"],destinations)) print "possible_policy_overlap:" s
	}
}
