function fail(message) {
	failed = 1
	printf "Profile line %d: %s\n", NR, message > "/dev/stderr"
	exit 1
}

function require(ok) {
	if (!ok) fail("Invalid or unsupported option value.")
}

function uint(value, max) {
	return value ~ /^(0|[1-9][0-9]*)$/ && length(value) <= 9 && value + 0 <= max
}

function ipv4(value, parts, count, i) {
	count = split(value, parts, ".")
	if (count != 4) return 0
	for (i = 1; i <= 4; i++) if (!uint(parts[i], 255)) return 0
	return 1
}

function host(value, parts, count, i) {
	if (ipv4(value)) return 1
	if (length(value) > 253 || value !~ /^[a-zA-Z0-9.-]+$/) return 0
	count = split(value, parts, ".")
	if (parts[count] !~ /[a-zA-Z]/) return 0
	for (i = 1; i <= count; i++) {
		if (length(parts[i]) < 1 || length(parts[i]) > 63) return 0
		if (parts[i] ~ /^-/ || parts[i] ~ /-$/) return 0
	}
	return 1
}

function fingerprint(value, parts, count, i) {
	count = split(value, parts, ":")
	if (count != 32) return 0
	for (i = 1; i <= count; i++) if (parts[i] !~ /^[a-fA-F0-9][a-fA-F0-9]$/) return 0
	return 1
}

function quoted(value, out, i, ch) {
	out = "\""
	for (i = 1; i <= length(value); i++) {
		ch = substr(value, i, 1)
		if (ch == "\\" || ch == "\"") out = out "\\"
		out = out ch
	}
	return out "\""
}

function tokenize(line, i, ch, quote, token, started, escaped) {
	delete arg
	argc = 0
	for (i = 1; i <= length(line); i++) {
		ch = substr(line, i, 1)
		if (escaped) {
			if (ch != "\\" && ch != "\"" && ch != " " && ch != "\t") fail("Invalid escape.")
			token = token ch
			escaped = 0
		} else if (ch == "\\" && quote != "'") {
			escaped = started = 1
		} else if (quote != "") {
			if (ch == quote) {
				quote = ""
				if (i < length(line) && substr(line, i + 1, 1) !~ /[ \t]/) fail("Separate quoted arguments with whitespace.")
			} else token = token ch
		} else if (ch ~ /[ \t]/) {
			if (started) arg[++argc] = token
			token = ""
			started = 0
		} else if (!started && (ch == "#" || ch == ";")) {
			break
		} else if (!started && (ch == "\"" || ch == "'")) {
			quote = ch
			started = 1
		} else {
			token = token ch
			started = 1
		}
		if (length(token) > 1024 || argc > 16) fail("Too many or oversized arguments.")
	}
	if (quote != "" || escaped) fail("Unfinished quote or escape.")
	if (started) arg[++argc] = token
	if (argc > 16) fail("Too many arguments.")
}

function emit(i, line) {
	line = arg[1]
	for (i = 2; i <= argc; i++) line = line " " quoted(arg[i])
	body = body line "\n"
}

function inline_line(line, clean, label) {
	clean = line
	gsub(/^[ \t]+|[ \t]+$/, "", clean)
	if (clean == "</" block ">") {
		if (block == "peer-fingerprint") require(block_items > 0)
		else require(pem == "" && block_items > 0)
		if (block == "tls-auth" || block == "tls-crypt") require(hex_bytes == 512)
		body = body clean "\n"
		block = ""
		return
	}
	if (clean ~ /[<>]/) fail("Malformed inline block.")
	if (block == "peer-fingerprint") {
		require(fingerprint(clean) && ++block_items <= 8)
	} else if (clean == "" || clean ~ /^#/) {
		# inline comments remain data, including words that look like options
	} else if (clean ~ /^-----BEGIN /) {
		require(pem == "")
		label = clean
		sub(/^-----BEGIN /, "", label)
		sub(/-----$/, "", label)
		if (block == "ca" || block == "cert") require(label == "CERTIFICATE")
		else if (block == "key") {
			if (label == "ENCRYPTED PRIVATE KEY") fail("Encrypted private keys are not supported.")
			require(label ~ /^(PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)$/)
		}
		else if (block == "tls-auth" || block == "tls-crypt") require(label == "OpenVPN Static key V1")
		else require(label == "OpenVPN tls-crypt-v2 client key")
		pem = label
		pem_items = 0
		padded = 0
	} else if (clean ~ /^-----END /) {
		require(pem != "" && clean == "-----END " pem "-----" && pem_items > 0)
		pem = ""
		block_items++
	} else {
		require(pem != "")
		if (block == "tls-auth" || block == "tls-crypt") {
			require(clean ~ /^[a-fA-F0-9]+$/)
			hex_bytes += length(clean)
		} else {
			require(!padded && clean ~ /^[a-zA-Z0-9+\/]+=?=?$/ && length(clean) % 4 == 0)
			if (clean ~ /=/) padded = 1
		}
		pem_items++
	}
	body = body line "\n"
}

{
	line = $0
	sub(/\r$/, "", line)
	if (length(line) > 2048 || line ~ /\r/) fail("Oversized line or invalid line ending.")
	if (block != "") {
		inline_line(line)
		next
	}
	tokenize(line)
	if (!argc) next
	name = arg[1]
	sub(/^--/, "", name)
	arg[1] = name
	if (name ~ /^<[a-z][a-z0-9-]*>$/) {
		require(argc == 1)
		block = substr(name, 2, length(name) - 2)
		if (block !~ /^(ca|cert|key|tls-auth|tls-crypt|tls-crypt-v2|peer-fingerprint)$/) fail("Unsupported inline block.")
		if (blocks[block]++) fail("Duplicate inline block.")
		block_items = hex_bytes = 0
		body = body "<" block ">\n"
		next
	}
	if (name !~ /^[a-z][a-z0-9-]*$/) fail("Unsupported profile option.")
	if (name != "remote" && name != "peer-fingerprint" && name != "pull-filter" && name !~ /^(route|route-ipv6|dhcp-option|dns)$/) {
		if (options[name]++) fail("Duplicate profile option.")
	}
	if (name ~ /^(client|tls-client|pull)$/) {
		require(argc == 1)
		if (name != "pull") client = 1
		next
	} else if (name == "dev") {
		require(argc == 2 && arg[2] ~ /^[a-zA-Z][a-zA-Z0-9_.-]*$/ && length(arg[2]) <= 15 && arg[2] !~ /^tap/)
		device_changed = 1
		next
	} else if (name == "dev-type") {
		require(argc == 2 && arg[2] == "tun")
		next
	} else if (name == "remote") {
		require(argc >= 2 && argc <= 4 && host(arg[2]) && ++remotes <= 16)
		if (argc >= 3) require(uint(arg[3], 65535) && arg[3] + 0 > 0)
		if (argc == 4) require(arg[4] ~ /^(udp[46]?|tcp[46]?-client)$/)
	} else if (name == "proto") {
		require(argc == 2 && arg[2] ~ /^(udp[46]?|tcp[46]?-client)$/)
	} else if (name == "port" || name == "rport") {
		require(argc == 2 && uint(arg[2], 65535) && arg[2] + 0 > 0)
	} else if (name == "auth-user-pass") {
		require(argc <= 2)
		auth_required = 1
		next
	} else if (name ~ /^(ca|cert|key|tls-auth|tls-crypt|tls-crypt-v2)$/) {
		if (arg[2] != "[inline]") fail("External certificate and key files are not supported.")
		require(argc == 2 || (name == "tls-auth" && argc == 3 && arg[3] ~ /^[01]$/))
		if (argc == 3) {
			require(direction == "" || direction == arg[3])
			direction = arg[3]
		}
		inline_refs[name] = 1
		next
	} else if (name == "peer-fingerprint") {
		require(argc == 2 && fingerprint(arg[2]))
		pins++
	} else if (name == "remote-cert-tls") {
		require(argc == 2 && arg[2] == "server")
		verify_server = 1
	} else if (name == "verify-x509-name") {
		require((argc == 2 || argc == 3) && length(arg[2]) > 0 && length(arg[2]) <= 256)
		if (argc == 3) require(arg[3] ~ /^(name|subject)$/)
		verify_server = 1
	} else if (name == "tls-version-min" || name == "tls-version-max") {
		require(argc == 2 && arg[2] ~ /^1\.[23]$/)
		if (name == "tls-version-min") tls_min = arg[2]
		else tls_max = arg[2]
	} else if (name == "key-direction") {
		require(argc == 2 && arg[2] ~ /^[01]$/ && (direction == "" || direction == arg[2]))
		direction = arg[2]
		next
	} else if (name ~ /^(cipher|data-ciphers|data-ciphers-fallback)$/) {
		require(argc == 2)
		count = split(arg[2], ciphers, ":")
		if (name != "data-ciphers") require(count == 1)
		for (i = 1; i <= count; i++) require(ciphers[i] ~ /^(AES-(128|192|256)-(GCM|CBC)|CHACHA20-POLY1305)$/)
	} else if (name == "auth") {
		require(argc == 2 && arg[2] ~ /^SHA(1|256|384|512)$/)
	} else if (name ~ /^(redirect-gateway|redirect-private|route|route-ipv6|route-delay|route-metric|route-noexec)$/) {
		require(argc <= 9)
		if (name == "route") require(argc >= 2 && argc <= 5)
		else if (name == "route-ipv6") require(argc >= 2 && argc <= 4)
		else if (name == "route-noexec") require(argc == 1)
		else if (name == "route-metric") require(argc == 2 && uint(arg[2], 16777216))
		else if (name == "route-delay") {
			require(argc <= 3)
			for (i = 2; i <= argc; i++) require(uint(arg[i], 86400))
		} else {
			for (i = 2; i <= argc; i++) require(arg[i] ~ /^(local|autolocal|def1|bypass-dhcp|bypass-dns|block-local|ipv6|!ipv4)$/)
		}
		removed_routes++
		next
	} else if (name ~ /^(dhcp-option|dns|block-outside-dns)$/) {
		require(name == "block-outside-dns" ? argc == 1 : argc >= 2)
		removed_dns++
		next
	} else if (name == "pull-filter") {
		require(argc == 3 && arg[2] ~ /^(accept|ignore|reject)$/)
		replaced_filters++
		next
	} else if (name == "route-nopull") {
		require(argc == 1)
		next
	} else if (name == "route-gateway") {
		require(argc == 2 && (ipv4(arg[2]) || arg[2] == "dhcp"))
	} else if (name == "ifconfig") {
		require(argc == 3 && ipv4(arg[2]) && ipv4(arg[3]))
	} else if (name == "topology") {
		require(argc == 2 && arg[2] ~ /^(subnet|net30|p2p)$/)
	} else if (name ~ /^(persist-key|persist-tun|nobind|remote-random|remote-random-hostname|auth-nocache|mute-replay-warnings|disable-dco)$/) {
		require(argc == 1)
		if (name == "nobind" || name == "auth-nocache") next
	} else if (name == "auth-retry") {
		require(argc == 2 && arg[2] ~ /^(nointeract|none)$/)
	} else if (name == "allow-compression") {
		require(argc == 2 && arg[2] == "no")
		next
	} else if (name == "comp-lzo") {
		require(argc == 2 && arg[2] == "no")
		next
	} else if (name == "resolv-retry") {
		require(argc == 2 && (arg[2] == "infinite" || uint(arg[2], 3600)))
	} else if (name == "connect-retry" || name == "keepalive") {
		require((argc == 3 || (name == "connect-retry" && argc == 2)) && uint(arg[2], 3600) && arg[2] + 0 > 0)
		if (argc == 3) require(uint(arg[3], 3600) && arg[3] + 0 >= arg[2] + 0)
	} else if (name ~ /^(ping|ping-restart|connect-timeout|connect-retry-max|tls-timeout|hand-window|reneg-sec|tun-mtu|mssfix|sndbuf|rcvbuf|mute|verb)$/) {
		require(argc == 2 && uint(arg[2], 16777216))
		if (name == "verb") require(arg[2] + 0 <= 4)
		if (name == "tun-mtu") require(arg[2] + 0 >= 576 && arg[2] + 0 <= 9000)
	} else if (name == "explicit-exit-notify") {
		require(argc == 1 || (argc == 2 && uint(arg[2], 5)))
	} else fail("Unsupported profile option.")
	emit()
}

END {
	if (failed) exit 1
	if (block != "") fail("Unclosed inline block.")
	if (!client) fail("A TLS client profile is required.")
	if (!remotes) fail("At least one remote endpoint is required.")
	for (name in inline_refs) if (!blocks[name]) fail("An inline certificate or key block is missing.")
	if ((blocks["cert"] > 0) != (blocks["key"] > 0)) fail("Include both the client certificate and its private key.")
	require(blocks["tls-auth"] + blocks["tls-crypt"] + blocks["tls-crypt-v2"] <= 1)
	if (direction != "") require(blocks["tls-auth"])
	if (tls_max != "" && tls_min != "") require(tls_max + 0 >= tls_min + 0)
	if (blocks["peer-fingerprint"]) pins++
	if (!pins && !(blocks["ca"] && verify_server)) fail("Include a CA and server identity check, or a SHA256 peer fingerprint.")
	print "client\ndev " device "\ndev-type tun\nnobind\nroute-nopull" > output
	print "pull-filter ignore \"redirect-\"\npull-filter ignore \"dhcp-option\"\npull-filter ignore \"dns\"\npull-filter ignore \"block-outside-dns\"" > output
	print "pull-filter ignore \"compress\"\npull-filter ignore \"comp-lzo\"\npull-filter ignore \"allow-compression\"\nallow-compression no" > output
	print "pull-filter ignore \"setenv\"\npull-filter ignore \"ifconfig-ipv6\"" > output
	if (tls_min == "") print "tls-version-min 1.2" > output
	if (auth_required) print "auth-user-pass " quoted(credentials) "\nauth-nocache" > output
	if (direction != "") print "key-direction " direction > output
	printf "%s", body > output
	close(output)
	print "remote_count=" remotes > summary
	print "auth_required=" (auth_required ? 1 : 0) > summary
	print "client_certificate=" (blocks["cert"] ? 1 : 0) > summary
	print "peer_verification=" (pins ? "fingerprint" : "ca") > summary
	print "removed_routes=" (removed_routes + 0) > summary
	print "removed_dns=" (removed_dns + 0) > summary
	print "replaced_filters=" (replaced_filters + 0) > summary
	print "device_replaced=" (device_changed + 0) > summary
	print "device=" device > summary
	close(summary)
}
