# strip only PBR's own mount from a canonical export
{
	if (!quoted && $0 ~ /^package /) next
	if (!quoted && $0 ~ /^config /) dnsmasq = ($0 ~ /^config dnsmasq( |$)/)
	if (!keep_mount && !quoted && dnsmasq && $0 == "\tlist addnmount '/var/run/pbr.dnsmasq'") next
	print
	for (i = 1; i <= length($0); i++) {
		c = substr($0, i, 1)
		if (!quoted && c == "\\") { i++; continue }
		if (c == "'") quoted = !quoted
	}
}
END { if (quoted) exit 1 }
