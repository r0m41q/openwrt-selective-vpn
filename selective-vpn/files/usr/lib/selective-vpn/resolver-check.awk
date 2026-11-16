FILENAME == destinations { domain[$0]=1; next }
FILENAME == sets { known[$0]=1; next }
/^nftset=\// {
	n = split($0, parts, "/")
	if (n != 3 || !(parts[2] in domain)) next
	count = split(parts[3], specs, /[, \t]+/)
	for (i=1; i<=count; i++) {
		if (specs[i] !~ /^4#inet#fw4#pbr_[a-zA-Z0-9_]+$/) continue
		split(specs[i], fields, "#")
		if (fields[4] in known) found[parts[2]]=1
	}
}
END { for (name in domain) if (!(name in found)) exit 1 }
