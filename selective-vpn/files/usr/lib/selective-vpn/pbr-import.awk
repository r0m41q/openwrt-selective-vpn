# modes: scan checks hand-made PBR policies, name gives unnamed policies a
# section name, merge adds converted policies to the draft rules
BEGIN { FS = "\t"; OFS = "\t" }
function fail() { bad = 1; exit 1 }
function ipv4(value,    a, n, i) {
	n = split(value, a, ".")
	if (n != 4) return 0
	for (i = 1; i <= 4; i++) if (a[i] !~ /^(0|[1-9][0-9]?[0-9]?)$/ || a[i] + 0 > 255) return 0
	return 1
}
# sorted unique words joined by single spaces
function norm(text,    a, n, i, j, t, out, last) {
	n = split(text, a, / +/)
	for (i = 2; i <= n; i++) for (j = i; j > 1 && a[j - 1] > a[j]; j--) { t = a[j]; a[j] = a[j - 1]; a[j - 1] = t }
	for (i = 1; i <= n; i++) if (a[i] != "" && a[i] != last) { out = out (out == "" ? "" : " ") a[i]; last = a[i] }
	return out
}
function has(text, value) { return (" " text " ") ~ (" " value " ") }
function add(text, value) { return has(text, value) ? text : (text == "" ? value : text " " value) }
function words(text,    a) { return split(text, a, / +/) }
function fresh(address,    base, candidate, i) {
	base = "device_" address
	gsub(/\./, "_", base)
	candidate = base
	for (i = 2; candidate in used; i++) candidate = base "_" i
	used[candidate] = 1
	return candidate
}
function report(i, status, rule) { print c[i, 1], c[i, 2], c[i, 3], status, rule > out }

mode == "scan" && FILENAME ~ /\/interfaces$/ { if ($0 != "") candidate[$0] = 1; next }
mode == "scan" {
	if ($1 == "S") { type[$2] = $3; name[$2] = $4; if ($2 + 0 > last) last = $2 + 0 }
	else if ($1 == "V") {
		# BusyBox creates the element before testing it inside an assignment
		key = $2 SUBSEP $3
		if (key in v) v[key] = v[key] " " $4
		else v[key] = $4
	}
	next
}

mode == "name" && FILENAME ~ /\/rename$/ { rename[$1] = $2; wanted++; next }
mode == "name" {
	if (!quoted) {
		if (FNR == 1 && $0 ~ /^package /) { header = 1; next }
		if (header && FNR == 2 && $0 == "") next
		if ($0 ~ /^config [a-zA-Z0-9_-]+/) {
			sections++
			if (sections in rename) {
				if ($0 !~ /^config policy$/) fail()
				$0 = $0 " '" rename[sections] "'"
				done++
			}
		}
	}
	print
	for (pos = 1; pos <= length($0); pos++) {
		ch = substr($0, pos, 1)
		if (!quoted && ch == "\\") { pos++; continue }
		if (ch == "'") quoted = !quoted
	}
	next
}

mode == "merge" && FILENAME ~ /\/draft$/ {
	key = $0; sub(/ .*/, "", key)
	rest = $0; sub(/^[^ ]+ ?/, "", rest)
	if (key == "rule") { n++; rname[n] = rest; used[rest] = 1; if (rest == "global") global = n }
	else if (key == "address") raddr[n] = rest
	else if (key == "proto") rproto[n] = rest
	else if (key == "dest_port") rports[n] = rest
	else if (key == "destinations") rdest[n] = rest
	else if (key == "preset") rpreset[n] = rest
	else if (key == "adopt") radopt[n] = rest
	else if (key != "") fail()
	next
}
mode == "merge" { m++; for (i = 1; i <= 8; i++) c[m, i] = $i; next }

END {
	if (bad) exit 1
	if (mode == "name") exit (quoted || done != wanted)
	if (mode == "scan") {
		for (s = 1; s <= last; s++) {
			if (type[s] != "policy" && type[s] != "dns_policy") continue
			if (name[s] ~ /^svpn_/) continue
			label = v[s, "name"]
			gsub(/[^ -~]/, "", label)
			label = substr(label, 1, 64)
			src = v[s, "src_addr"]; sub(/\/32$/, "", src)
			proto = v[s, "proto"]
			if (proto == "" || proto == "all") proto = "tcp udp"
			proto = norm(proto)
			status = "ok"
			if (type[s] == "dns_policy") status = "dns_policy"
			else if (v[s, "enabled"] == "0") status = "disabled"
			else if (!(v[s, "interface"] in candidate)) status = "interface"
			else if (v[s, "chain"] != "" && v[s, "chain"] != "prerouting") status = "chain"
			else if (v[s, "src_port"] != "") status = "source_port"
			else if (src != "" && !ipv4(src)) status = "sources"
			else if (v[s, "dest_addr"] == "" || v[s, "dest_addr"] ~ /[!@]/) status = "destinations"
			else if (proto != "tcp" && proto != "udp" && proto != "tcp udp") status = "protocol"
			# a separator that is not whitespace keeps empty fields for read
			printf "%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n", s, name[s], label, status, src, proto, v[s, "dest_port"], v[s, "dest_addr"]
		}
		exit
	}
	if (!global) exit 1
	original = n
	for (j = 1; j <= n; j++) { k = split(radopt[j], t, " "); while (k) owner[t[k--]] = j }
	# Global first, so a new device rule starts from the imported Global routes
	for (pass = 1; pass <= 2; pass++) for (i = 1; i <= m; i++) {
		address = c[i, 4]
		if ((address == "") != (pass == 1)) continue
		if (c[i, 2] in owner) { report(i, "adopted", rname[owner[c[i, 2]]]); continue }
		r = 0; made = 0
		if (address == "") r = global
		else for (j = 1; j <= n; j++) if (raddr[j] == address) r = j
		if (!r) {
			if (n >= 24) { report(i, "rules_limit", ""); continue }
			r = ++n; made = 1
			rname[r] = fresh(address); raddr[r] = address
			rproto[r] = rproto[global]; rports[r] = rports[global]
			rdest[r] = rdest[global]; rpreset[r] = rpreset[global]; radopt[r] = ""
		}
		if (c[i, 8] != "") rpreset[r] = add(rpreset[r], c[i, 8])
		else if (rdest[r] == "") { rproto[r] = c[i, 5]; rports[r] = c[i, 6]; rdest[r] = c[i, 7] }
		else if (norm(rproto[r] == "" ? "tcp udp" : rproto[r]) == norm(c[i, 5]) && norm(rports[r]) == norm(c[i, 6])) {
			joined = norm(rdest[r] " " c[i, 7])
			if (words(joined) > 64 || length(joined) > 4000) {
				report(i, "too_many_destinations", rname[r])
				if (made) { delete used[rname[r]]; n-- }
				continue
			}
			rdest[r] = joined
		} else {
			report(i, "conflict", rname[r])
			if (made) { delete used[rname[r]]; n-- }
			continue
		}
		radopt[r] = add(radopt[r], c[i, 2])
		if (address == "") global_imported = 1
		report(i, "imported", rname[r])
	}
	# devices with their own rule never use Global routes
	if (global_imported) for (r = 1; r <= original; r++) if (r != global) print "", "", "", "global_skips", rname[r] > out
	for (r = 1; r <= n; r++) {
		print "rule " rname[r]
		if (raddr[r] != "") print "address " raddr[r]
		if (rproto[r] != "") print "proto " rproto[r]
		if (rports[r] != "") print "dest_port " rports[r]
		if (rdest[r] != "") print "destinations " rdest[r]
		if (rpreset[r] != "") print "preset " rpreset[r]
		if (radopt[r] != "") print "adopt " radopt[r]
	}
}
