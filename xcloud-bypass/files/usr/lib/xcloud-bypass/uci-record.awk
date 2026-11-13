# input must be a canonical uci -N export
function fail() { bad = 1; exit 1 }

function consume(text,    i, c, name, fields, count) {
	if (text ~ /^[ \t\n]*$/) return
	count = split(text, fields, /[ \t\n]+/)
	if (fields[1] == "package") {
		if (section_seen || package_seen++) fail()
		return
	}
	if (fields[1] == "config") {
		section_seen = 1
		name = fields[3]
		if (name ~ /^'[a-zA-Z0-9_]+'$/) name = substr(name, 2, length(name) - 2)
		else name = ""
		if (name != "" && names[name]++) fail()
		current = name
		if (current == section) found_section = 1
		command[++commands] = text
		selected[commands] = (current == section && option == "")
		in_section[commands] = (current == section)
		return
	}
	if (!section_seen || text !~ /^\t(option|list) [a-zA-Z0-9_]+ '/) fail()
	command[++commands] = text
	in_section[commands] = (current == section)
	selected[commands] = (current == section && (option == "" || fields[3] == option))
}

{
	if (!quoted && buffer == "" && $0 == "") next
	buffer = buffer $0 "\n"
	for (pos = 1; pos <= length($0); pos++) {
		char = substr($0, pos, 1)
		if (!quoted && char == "\\") { pos++; continue }
		if (char == "'") quoted = !quoted
	}
	if (!quoted) { consume(buffer); buffer = "" }
}

END {
	if (bad || quoted || buffer != "") exit 1
	if (mode != "read" && mode != "replace") exit 1
	if (mode == "replace") {
		while ((getline line < replacement) > 0) value = value line "\n"
		close(replacement)
		if (option != "" && !found_section) exit 1
	}
	for (i = 1; i <= commands; i++) {
		if (mode == "read") {
			if (selected[i]) printf "%s", command[i]
			continue
		}
		if (selected[i]) {
			if (!inserted++) printf "%s", value
		} else {
			printf "%s", command[i]
		}
		if (option != "" && !inserted && in_section[i] && !in_section[i + 1]) {
			printf "%s", value
			inserted = 1
		}
	}
	if (mode == "replace" && !inserted) printf "%s", value
}
