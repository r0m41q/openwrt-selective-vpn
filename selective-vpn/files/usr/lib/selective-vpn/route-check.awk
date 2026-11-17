# compare main routes while allowing only connected IPv4 tunnel routes
function number(ip, a, n, i, value) {
	n = split(ip, a, ".")
	if (n != 4) return -1
	for (i = 1; i <= 4; i++) {
		if (a[i] !~ /^[0-9]+$/ || a[i] + 0 > 255) return -1
		value = value * 256 + a[i]
	}
	return value
}
function interval(cidr, a, i, size, value) {
	split(cidr, a, "/")
	value = number(a[1])
	if (value < 0 || a[2] !~ /^[0-9]+$/ || a[2] > 32) return 0
	size = 1
	for (i = a[2]; i < 32; i++) size *= 2
	start = int(value / size) * size; finish = start + size - 1
	return 1
}
FILENAME == eligible {
	if (!interval($0)) { bad = 1; next }
	low[++nets] = start; high[nets] = finish
	next
}
{
	dev = ""; proto = ""; via = 0; normalized = ""
	for (i = 1; i <= NF; i++) {
		if ($i == "dev") dev = $(i + 1)
		if ($i == "proto") proto = $(i + 1)
		if ($i == "via") via = 1
		if ($i == "expires") { i++; continue }
		normalized = normalized (normalized == "" ? "" : " ") $i
	}
	if (dev != "" && index(skip, " " dev " ")) next
	if (dev == tun || (old_tun != "" && dev == old_tun)) {
		if (family == 6 || via || proto != "kernel" || $1 == "default") { bad = 1; next }
		cidr = $1
		if (index(cidr, "/") == 0) cidr = cidr "/32"
		if (!interval(cidr) || cidr ~ /\/([0-7])$/) { bad = 1; next }
		for (i = 1; i <= nets; i++) if (start <= high[i] && finish >= low[i]) bad = 1
		next
	}
	if (FILENAME == before) old[normalized]++
	else current[normalized]++
}
END {
	for (line in old) if (old[line] != current[line]) bad = 1
	for (line in current) if (current[line] != old[line]) bad = 1
	exit bad
}
