#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C
LC_ALL=C
APK_CONFIG=/dev/null
export APK_CONFIG
unset SSL_NO_VERIFY_HOSTNAME
umask 077

readonly backup='/etc/selective-vpn-install'
readonly world='/etc/apk/world'
readonly config='/etc/config'
readonly init='/etc/init.d'
readonly private='/etc/selective-vpn'
readonly temporary='/tmp'
readonly runtime='/var/run/selective-vpn'
readonly proc='/proc'
readonly release_url='https://github.com/r0m41q/openwrt-selective-vpn/releases/download'
readonly saved_files='network firewall pbr dhcp openvpn selective-vpn'
work=''
locked=0
armed=0
version=''
checksum=''
luci_checksum=''
recover=0

die() {
	printf '%s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<'EOF'
Usage: sh install.sh --version VERSION --sha256 SHA256 [--luci-sha256 SHA256]
       sh install.sh --recover

Use the APK version and SHA256 from a trusted, versioned release.
Packages must be signed by a key already trusted by APK.
Add --luci-sha256 to install the matching LuCI package on a router with LuCI.
EOF
}

safe_file() {
	[ -f "$1" ] && [ ! -L "$1" ] &&
		[ "$(stat -c '%u %h' "$1")" = '0 1' ] &&
		[ "$(wc -c < "$1")" -le 131072 ] &&
		[ "$((0$(stat -c '%a' "$1") & 0022))" -eq 0 ]
}

safe_directory() {
	[ -d "$1" ] && [ ! -L "$1" ] || return 1
	info=$(stat -c '%u %a' "$1") || return 1
	[ "${info%% *}" = 0 ] && [ "$((0${info#* } & 0022))" -eq 0 ]
}

replace_file() (
	safe_file "$1" && safe_directory "${2%/*}" || exit 1
	if [ -e "$2" ] || [ -L "$2" ]; then safe_file "$2" || exit 1; fi
	copy=$(mktemp "${2%/*}/.selective-vpn-install.XXXXXXXX") || exit 1
	trap 'rm -f "$copy"' EXIT
	cp -p "$1" "$copy" && mv "$copy" "$2"
)

apk_run() {
	apk --check-certificate --no-interactive \
		--no-progress --no-logfile --timeout 30 --cache-dir "$work/cache" "$@"
}

manifest() {
	apk_run list --installed --manifest > "$work/manifest.raw" || return 1
	awk 'NF != 2 || $1 !~ /^[a-zA-Z0-9][a-zA-Z0-9+_.-]*$/ ||
		$2 !~ /^[a-zA-Z0-9][a-zA-Z0-9+_.~-]*$/ || seen[$1]++ { exit 1 }
		END { if (NR == 0) exit 1 }' "$work/manifest.raw" || return 1
	sort "$work/manifest.raw"
}

installed_version() {
	awk -v name="$1" '$1 == name { print $2 }' "$work/before"
}

confirm() {
	printf '%s' "$1 [y/N] "
	IFS= read -r answer || return 1
	case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

space() {
	free=$(df -Pk "$1" | awk 'END { print $4 }') || return 1
	case "$free" in ''|*[!0-9]*) return 1 ;; esac
	[ "$free" -ge "$2" ]
}

fetch_release() {
	name=$1
	expected=$2
	file="$work/new/$name-$version.apk"
	curl --disable --fail --silent --show-error --location --proto '=https' \
		--proto-redir '=https' --connect-timeout 10 --max-time 120 \
		--max-filesize 8388608 --output "$file" \
		"$release_url/v$version/$name-$version.apk" || die 'Release download failed.'
	actual=$(sha256sum "$file") || die 'Cannot check the release checksum.'
	[ "${actual%% *}" = "$expected" ] || die 'Release checksum does not match.'
	check_package "$file" "$name" "$version" noarch
}

cache_previous() {
	case "$1" in
		selective-vpn|luci-app-selective-vpn)
			previous="$work/old/$1-$2.apk"
			curl --disable --fail --silent --show-error --location --proto '=https' \
				--proto-redir '=https' --connect-timeout 10 --max-time 120 \
				--max-filesize 8388608 --output "$previous" \
				"$release_url/v$2/$1-$2.apk" || die 'Cannot download the previous release for recovery.'
			check_package "$previous" "$1" "$2" noarch ;;
		*) apk_run fetch --output "$work/old" "$1=$2" > /dev/null ||
			die 'Cannot cache the previous package. Keep the current installation until its signed APK is available.' ;;
	esac
}

lock_backend() {
	[ ! -e "$runtime" ] && [ ! -L "$runtime" ] && return 0
	command -v flock > /dev/null 2>&1 && safe_directory "$runtime" || return 1
	for name in lifecycle.lock lock; do
		if [ ! -e "$runtime/$name" ] && [ ! -L "$runtime/$name" ]; then
			(set -C; : > "$runtime/$name") || return 1
		fi
		safe_file "$runtime/$name" || return 1
	done
	exec 8<> "$runtime/lifecycle.lock" 9<> "$runtime/lock"
	flock -n 8 && flock -n 9
}

check_package() {
	apk_run verify "$1" > /dev/null || die 'APK signature verification failed. Check the trusted signing key.'
	apk_run adbdump --format json "$1" > "$work/metadata" || die 'Cannot read APK metadata.'
	[ "$(jsonfilter -i "$work/metadata" -e '@.info.name')" = "$2" ] &&
		[ "$(jsonfilter -i "$work/metadata" -e '@.info.version')" = "$3" ] &&
		[ "$(jsonfilter -i "$work/metadata" -e '@.info.arch')" = "$4" ] ||
		die 'Unexpected package name, version, or architecture.'
}

parse_plan() {
	awk '/^\([0-9]+\/[0-9]+\) / {
		if ($2 !~ /^(Installing|Purging|Upgrading|Replacing)$/ || $3 !~ /^[a-zA-Z0-9][a-zA-Z0-9+_.-]*$/) exit 1
		name = $3
		if ($2 != "Installing" && name !~ /^(selective-vpn|luci-app-selective-vpn|dnsmasq|dnsmasq-dhcpv6)$/) exit 1
		if ($2 == "Purging") { print name, "-"; next }
		v = $NF; gsub(/[()]/, "", v)
		if (v !~ /^[a-zA-Z0-9][a-zA-Z0-9+_.~-]*$/) exit 1
		if (name == "pbr" && v !~ /^1\.2\.2-r[0-9]+$/) exit 1
		print name, v
	}' "$1"
}

dns_probe() {
	# query the local resolver explicitly; the system resolver may point elsewhere
	nslookup downloads.openwrt.org 127.0.0.1 > /dev/null 2>&1
}

dns_features() {
	dnsmasq --version > "$work/dns-version" 2>/dev/null || return 1
	awk '/^Compile time options:/ {
		for (i = 4; i <= NF; i++) if ($i == "nftset") found = 1
	} END { exit !found }' "$work/dns-version"
}

dns_listener() (
	pid=$(jsonfilter -i "$work/dns-service" -e '@.dnsmasq.instances.*.pid') || exit 1
	case "$pid" in ''|*[!0-9]*) exit 1 ;; esac
	: > "$work/dns-sockets"
	for fd in "$proc/$pid/fd/"*; do
		link=$(readlink "$fd" 2>/dev/null) || continue
		case "$link" in socket:\[*\]) printf '%s\n' "$link" >> "$work/dns-sockets" ;; esac
	done
	: > "$work/dns-listeners"
	for table in tcp udp tcp6 udp6; do
		[ -f "$proc/net/$table" ] || continue
		awk -v table="$table" '$2 ~ /:0035$/ && (table ~ /^udp/ || $4 == "0A") {
			print "socket:[" $10 "]"
			if (table == "tcp" && $2 ~ /^(00000000|0100007F):/) tcp = 1
			if (table == "udp" && $2 ~ /^(00000000|0100007F):/) udp = 1
		} END { if (tcp) print "tcp"; if (udp) print "udp" }' "$proc/net/$table" >> "$work/dns-listeners"
	done
	awk 'FILENAME == ARGV[1] { owned[$0] = 1; next }
		$0 == "tcp" { tcp = 1; next } $0 == "udp" { udp = 1; next }
		!($0 in owned) { bad = 1 }
		END { exit (bad || !tcp || !udp) }' "$work/dns-sockets" "$work/dns-listeners"
)

check_dns() {
	for name in adguardhome AdGuardHome unbound smartdns bind-server kresd; do
		[ -z "$(installed_version "$name")" ] ||
			die 'Another DNS resolver is installed. Configure dnsmasq nftset integration manually first.'
	done
	uci -q export dhcp > "$work/dhcp" || die 'Cannot read DHCP configuration.'
	[ "$(awk '$1 == "config" && $2 == "dnsmasq" { n++ } END { print n+0 }' "$work/dhcp")" = 1 ] ||
		die 'Automatic installation requires one dnsmasq instance.'
	if awk '$1 == "config" { section = $2; gsub(/\047/, "", section) }
	section == "dnsmasq" && ($1 == "option" || $1 == "list") {
		key = $2; value = $3; gsub(/\047/, "", key); gsub(/\047/, "", value)
		if (key ~ /^(confdir|serversfile|interface|notinterface|listen_address)$/) bad = 1
		if (key == "port" && value != "53") bad = 1
		if (key == "leasefile" && value != "/tmp/dhcp.leases") bad = 1
		if (key == "resolvfile" && value != "/tmp/resolv.conf.d/resolv.conf.auto") bad = 1
		if (key == "noresolv" && value != "0") bad = 1
		if (key == "localservice" && value != "1") bad = 1
	} END { exit !bad }' "$work/dhcp"; then
		die 'Custom DNS listeners or files need manual DNS preparation.'
	fi
	[ ! -d /etc/dnsmasq.d ] || [ -z "$(ls -A /etc/dnsmasq.d)" ] ||
		die 'Custom dnsmasq snippets need manual DNS preparation.'
	safe_file /etc/dnsmasq.conf || die 'Unsafe dnsmasq configuration file.'
	if awk '!/^[ \t]*(#|$)/ { bad = 1 } END { exit !bad }' /etc/dnsmasq.conf; then
		die 'Custom dnsmasq options need manual DNS preparation.'
	fi
	ubus call service list '{"name":"dnsmasq"}' > "$work/dns-service" || die 'Cannot inspect dnsmasq.'
	[ "$(jsonfilter -i "$work/dns-service" -e '@.dnsmasq.instances.*.running')" = true ] ||
		die 'The local dnsmasq service must be running.'
	dns_listener || die 'dnsmasq must own the local TCP and UDP DNS listeners. Prepare custom DNS layouts manually.'
	dns_probe || die 'The local DNS resolver is not working.'
	dns_old=''
	for name in dnsmasq dnsmasq-dhcpv6 dnsmasq-full; do
		if [ -n "$(installed_version "$name")" ]; then
			[ -z "$dns_old" ] || die 'Multiple dnsmasq packages are installed.'
			dns_old=$name
		fi
	done
	[ -n "$dns_old" ] || die 'A packaged dnsmasq installation is required.'
	dns_change=0
	if ! dns_features; then
		[ "$dns_old" != dnsmasq-full ] || die 'dnsmasq-full has no nftset support. Use a compatible build.'
		dns_change=1
	fi
}

snapshot() {
	destination=$1
	mkdir -p "$destination"
	for name in $saved_files; do
		if [ -e "$config/$name" ] || [ -L "$config/$name" ]; then
			safe_file "$config/$name" || return 1
			cp -p "$config/$name" "$destination/$name" || return 1
		else
			: > "$destination/$name.absent"
		fi
	done
	safe_file /etc/dnsmasq.conf || return 1
	cp -p /etc/dnsmasq.conf "$destination/dnsmasq.conf"
}

same_snapshot() {
	for name in $saved_files; do
		if [ -f "$1/$name.absent" ]; then
			[ ! -e "$config/$name" ] && [ ! -L "$config/$name" ] || return 1
		else
			safe_file "$config/$name" && cmp -s "$config/$name" "$1/$name" || return 1
		fi
	done
	safe_file /etc/dnsmasq.conf && cmp -s /etc/dnsmasq.conf "$1/dnsmasq.conf"
}

restore_snapshot() {
	for name in $saved_files; do
		if [ -f "$backup/before-config/$name.absent" ]; then
			rm -f "$config/$name" || return 1
		else
			replace_file "$backup/before-config/$name" "$config/$name" || return 1
		fi
	done
	replace_file "$backup/before-config/dnsmasq.conf" /etc/dnsmasq.conf
}

recovery() {
	printf '%s\n' 'Restoring the previous application and DNS packages.' >&2
	safe_directory "$backup" && [ "$(stat -c '%a' "$backup")" = 700 ] || return 1
	[ -f "$backup/armed" ] || return 1
	for name in before allowed targets world; do safe_file "$backup/$name" || return 1; done
	# unknown edits after an interrupted APK script require manual review
	if [ -d "$backup/after-config" ]; then
		same_snapshot "$backup/after-config" || same_snapshot "$backup/before-config" || return 1
	else
		same_snapshot "$backup/before-config" || return 1
	fi
	manifest > "$work/current" || return 1
	awk 'FILENAME == ARGV[1] { old[$1] = $2; next }
		FILENAME == ARGV[2] { allowed[$1] = $2; next }
		{ if ($2 != old[$1] && $2 != allowed[$1]) bad = 1; seen[$1] = 1 }
		END { for (n in old) if (!seen[n] && !(n in allowed)) bad = 1; exit bad }' \
		"$backup/before" "$backup/allowed" "$work/current" || return 1
	# ignore only constraints this installer explicitly changed
	safe_file "$world" && safe_file "$backup/world" || return 1
	for source in current original; do
		case "$source" in current) path=$world ;; original) path=$backup/world ;; esac
		awk 'FILENAME == ARGV[1] { allowed[$1] = 1; next }
			{ name = $0; sub(/[@=<>~].*$/, "", name); if (!(name in allowed)) print }' \
			"$backup/targets" "$path" | sort > "$work/world.$source"
	done
	cmp -s "$work/world.current" "$work/world.original" || return 1
	set --
	for file in "$backup"/old/*.apk; do
		[ -f "$file" ] || continue
		apk_run verify "$file" > /dev/null || return 1
		set -- "$@" "$file"
	done
	while read -r name old_version; do
		case "$name" in selective-vpn|luci-app-selective-vpn|dnsmasq|dnsmasq-dhcpv6|dnsmasq-full) continue ;; esac
		set -- "$@" "$name=$old_version"
	done < "$backup/before"
	# the original world removes the new package constraints before solving recovery
	cp -p "$world" "$work/failed-world" || return 1
	replace_file "$backup/world" "$world" || return 1
	if ! apk_run --no-network add --simulate "$@" > "$work/recovery-plan" 2>&1; then
		replace_file "$work/failed-world" "$world"
		return 1
	fi
	if ! apk_run --no-network add "$@" > "$work/recovery-log" 2>&1; then
		return 1
	fi
	replace_file "$backup/world" "$world" || return 1
	restore_snapshot || return 1
	"$init/dnsmasq" restart > /dev/null 2>&1 && dns_probe || return 1
	manifest > "$work/restored" || return 1
	# dependencies installed along the way may remain, but original packages must match
	awk 'FILENAME == ARGV[1] { old[$1] = $2; next }
		{ if ($1 in old && old[$1] == $2) delete old[$1] }
		END { for (n in old) exit 1 }' "$backup/before" "$work/restored" || return 1
	cp -p "$work/restored" "$backup/installed" || return 1
	rm -f "$backup/armed"
	sync
	printf '%s\n' 'Previous packages and configuration restored.' >&2
}

cleanup() {
	result=$?
	trap - EXIT HUP INT TERM
	if [ "$armed" -eq 1 ]; then
		if ! recovery; then
			printf '%s\n' "Automatic recovery needs attention. Private backups: $backup" \
				'Run sh install.sh --recover after resolving conflicting edits.' >&2
		fi
		result=1
	fi
	[ -z "$work" ] || rm -rf "$work"
	if [ "$locked" -eq 1 ]; then
		rm -f "$temporary/selective-vpn-install.lock/pid"
		rmdir "$temporary/selective-vpn-install.lock"
	fi
	exit "$result"
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--help|-h) usage; exit 0 ;;
		--recover) recover=1; shift ;;
		--version|--sha256|--luci-sha256)
			[ "$#" -ge 2 ] || die 'Missing option value.'
			case "$1" in
				--version) [ -z "$version" ] || die 'Duplicate version.'; version=$2 ;;
				--sha256) [ -z "$checksum" ] || die 'Duplicate checksum.'; checksum=$2 ;;
				--luci-sha256) [ -z "$luci_checksum" ] || die 'Duplicate LuCI checksum.'; luci_checksum=$2 ;;
			esac
			shift 2 ;;
		*) die 'Unknown option. See --help.' ;;
	esac
done

[ "$(id -u)" = 0 ] || die 'Run this installer as root on OpenWrt.'
for tool in apk awk cat chmod cmp cp df du id mkdir mktemp mv nslookup readlink rm rmdir sha256sum sort stat sync wc; do
	command -v "$tool" > /dev/null 2>&1 || die "Missing required tool: $tool"
done
if [ "$recover" -eq 0 ]; then
	for tool in curl dnsmasq jsonfilter ls ubus uci; do
		command -v "$tool" > /dev/null 2>&1 || die "Missing required tool: $tool"
	done
fi
case "$(apk --version)" in apk-tools\ 3.*) ;; *) die 'APK 3 is required.' ;; esac
safe_directory /etc && safe_directory "$config" && safe_directory /etc/apk &&
	safe_directory "$init" && safe_file "$world" || die 'Unsafe system configuration paths.'
if [ "$recover" -eq 0 ]; then
	printf '%s\n' "$version" | awk '!/^[0-9]+\.[0-9]+\.[0-9]+-r[0-9]+$/ { exit 1 }' || die 'Use an exact APK version, for example 0.1.0-r1.'
	for digest in "$checksum" ${luci_checksum:+"$luci_checksum"}; do
		[ "${#digest}" -eq 64 ] || die 'A trusted SHA256 is required for each release package.'
		case "$digest" in *[!0-9a-f]*) die 'SHA256 must contain lowercase hexadecimal characters.' ;; esac
	done
else
	[ -z "$version$checksum$luci_checksum" ] || die '--recover takes no release options.'
fi

work=$(mktemp -d "$temporary/selective-vpn-install.XXXXXXXX") || die 'Cannot create private staging.'
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir "$work/cache" "$work/new" "$work/old"
if ! mkdir "$temporary/selective-vpn-install.lock" 2>/dev/null; then
	safe_directory "$temporary/selective-vpn-install.lock" &&
		safe_file "$temporary/selective-vpn-install.lock/pid" || die 'Unsafe installer lock.'
	pid=$(cat "$temporary/selective-vpn-install.lock/pid")
	case "$pid" in ''|*[!0-9]*) die 'Invalid installer lock.' ;; esac
	! kill -0 "$pid" 2>/dev/null || die 'Another installer is running.'
	rm "$temporary/selective-vpn-install.lock/pid"
	rmdir "$temporary/selective-vpn-install.lock"
	mkdir "$temporary/selective-vpn-install.lock" || die 'Another installer is starting.'
fi
locked=1
printf '%s\n' "$$" > "$temporary/selective-vpn-install.lock/pid"
lock_backend || die 'Selective VPN is busy or its locks are unsafe.'
if [ "$recover" -eq 1 ]; then
	confirm 'Restore the interrupted installation?' || exit 0
	recovery || die "Recovery stopped. Review the private files in $backup."
	exit 0
fi
if [ -e "$backup" ] || [ -L "$backup" ]; then
	safe_directory "$backup" && [ "$(stat -c '%a' "$backup")" = 700 ] &&
		[ ! -e "$backup/armed" ] && [ ! -L "$backup/armed" ] &&
		safe_file "$backup/before" || die "An interrupted installation exists at $backup. Run sh install.sh --recover."
	cp -p "$backup/first-installed" "$work/first-installed" || die 'Cannot read the installation history.'
fi
ubus call system board > "$work/board" || die 'Cannot identify this router.'
[ "$(jsonfilter -i "$work/board" -e '@.release.distribution')" = OpenWrt ] || die 'OpenWrt is required.'
firmware=$(jsonfilter -i "$work/board" -e '@.release.version') || die 'Cannot read the OpenWrt version.'
case "$firmware" in 25.12.[0-9]|25.12.[0-9][0-9]) ;; *) die 'This installer currently supports stable OpenWrt 25.12 releases.' ;; esac
architecture=$(apk --print-arch) || die 'Cannot read the APK architecture.'
case "$architecture" in ''|*[!a-zA-Z0-9_-]*) die 'Invalid APK architecture.' ;; esac
space / 32768 && space "$temporary" 32768 || die 'At least 32 MiB free flash and temporary space are required.'
manifest > "$work/before" || die 'Cannot read installed packages.'
case "$(installed_version pbr)" in ''|1.2.2-r[0-9]*) ;; *) die 'PBR 1.2.2 is required by this backend.' ;; esac
for name in $saved_files; do
	changes=$(uci -q changes "$name") || die 'Cannot check pending UCI edits.'
	[ -z "$changes" ] || die 'Commit or discard pending UCI edits before installation.'
done
luci='not installed'
[ -z "$(installed_version luci-base)" ] || luci='installed'
[ -z "$luci_checksum" ] || [ "$luci" = installed ] || die 'Install LuCI first, or omit --luci-sha256 for a backend-only installation.'
[ "$(uci -q get selective-vpn.main.enabled || true)" != 1 ] || die 'Disable routing before upgrading.'
[ ! -e "$private/pending" ] && [ ! -L "$private/pending" ] || die 'Resolve the pending routing change before installing.'
snapshot "$work/before-config" || die 'Cannot back up configuration safely.'
cp -p "$world" "$work/world"
check_dns
apk_run update > "$work/repositories" 2>&1 || die 'Package repositories are unavailable or cannot be verified.'
fetch_release selective-vpn "$checksum"
[ -z "$luci_checksum" ] || fetch_release luci-app-selective-vpn "$luci_checksum"
set -- "$work/new/selective-vpn-$version.apk"
printf '%s\n' selective-vpn > "$work/targets"
if [ -n "$luci_checksum" ]; then
	set -- "$@" "$work/new/luci-app-selective-vpn-$version.apk"
	printf '%s\n' luci-app-selective-vpn >> "$work/targets"
fi
if [ "$dns_change" -eq 1 ]; then
	set -- "$@" dnsmasq-full
	printf '%s\n' dnsmasq-full >> "$work/targets"
fi
apk_run add --simulate "$@" > "$work/plan" 2>&1 || die 'APK cannot install these packages without conflicts.'
parse_plan "$work/plan" > "$work/allowed" || die 'Installation would change an unrelated package, downgrade a package, or install an unsupported PBR version.'
while read -r name new_version; do
	[ "$new_version" != - ] || continue
	[ ! -f "$work/new/$name-$new_version.apk" ] || continue
	apk_run fetch --output "$work/new" "$name=$new_version" > /dev/null || die 'Cannot cache an installation package.'
done < "$work/allowed"
awk '$2 != "-" { print $1 }' "$work/allowed" >> "$work/targets"
while read -r name new_version; do
	old_version=$(installed_version "$name")
	[ -n "$old_version" ] || continue
	cache_previous "$name" "$old_version"
done < "$work/allowed"
required_kib=8192
for file in "$work/new"/*.apk "$work/old"/*.apk; do
	[ -f "$file" ] || continue
	apk_run verify "$file" > /dev/null || die 'A cached package failed signature verification.'
	apk_run adbdump --format json "$file" > "$work/metadata" || die 'Cannot read cached package metadata.'
	package_arch=$(jsonfilter -i "$work/metadata" -e '@.info.arch') || die 'Package architecture is missing.'
	[ "$package_arch" = noarch ] || [ "$package_arch" = "$architecture" ] || die 'Cached package architecture does not match.'
	bytes=$(jsonfilter -i "$work/metadata" -e '@.info["installed-size"]') || die 'Package size is missing.'
	case "$bytes" in ''|*[!0-9]*|??????????*) die 'Invalid package size.' ;; esac
	required_kib=$((required_kib + (bytes + 1023) / 1024))
done
cache_kib=$(du -sk "$work" | awk '{ print $1 }')
required_kib=$((required_kib + cache_kib))
space / "$required_kib" || die 'Insufficient flash for installation and recovery packages.'

printf '\nOpenWrt %s, architecture %s, LuCI %s\n' "$firmware" "$architecture" "$luci"
printf '%s\n' 'Proposed APK changes:'
cat "$work/plan"
if [ "$dns_change" -eq 1 ]; then
	printf '%s\n' 'Replace dnsmasq with dnsmasq-full. DNS and DHCP may pause briefly.'
fi
printf '%s\n' "Private recovery copy: $backup" 'Routing stays disabled. Existing VPN profiles and policies are preserved.'
confirm 'Install these packages?' || { printf '%s\n' 'Installation cancelled.'; exit 0; }
manifest > "$work/current"
cmp -s "$work/before" "$work/current" && cmp -s "$work/world" "$world" &&
	same_snapshot "$work/before-config" || die 'Configuration or packages changed during preparation. Run the installer again.'
for name in $saved_files; do
	[ -z "$(uci -q changes "$name")" ] || die 'Pending UCI edits appeared during preparation.'
done
# install only cached files, so DNS and repository changes cannot alter the proposal
set -- "$work/new/"*.apk
apk_run --no-network add --simulate "$@" > "$work/final-plan" 2>&1 || die 'Cached packages no longer satisfy the installation.'
parse_plan "$work/final-plan" > "$work/final-allowed" || die 'The cached package proposal is unsafe.'
sort "$work/allowed" > "$work/expected"
sort "$work/final-allowed" > "$work/proposed"
cmp -s "$work/expected" "$work/proposed" || die 'The cached package proposal changed. No packages were installed.'
[ ! -d "$backup" ] || rm -rf "$backup"
mkdir -m 700 "$backup"
cp -pR "$work/before-config" "$work/old" "$backup/"
cp -p "$work/before" "$work/world" "$work/allowed" "$work/targets" "$backup/"
if [ -f "$work/first-installed" ]; then
	cp -p "$work/first-installed" "$backup/first-installed"
else
	cp -p "$work/before" "$backup/first-installed"
fi
: > "$backup/armed"
sync
armed=1
install_result=0
apk_run --no-network add "$@" > "$work/install-log" 2>&1 || install_result=$?
snapshot "$backup/after-config" || die 'Cannot record the installation result.'
[ "$install_result" -eq 0 ] || die 'APK installation failed.'
[ "$(uci -q get selective-vpn.main.enabled || true)" != 1 ] || die 'The package unexpectedly enabled routing.'
for name in $saved_files; do
	[ ! -f "$backup/before-config/$name" ] ||
		cmp -s "$config/$name" "$backup/before-config/$name" || die 'A package script changed existing configuration.'
done
if [ "$dns_change" -eq 1 ]; then
	"$init/dnsmasq" restart > /dev/null 2>&1 || die 'Cannot restart dnsmasq-full.'
fi
dns_features && dns_probe || die 'The DNS check failed after installation.'
ubus call service list '{"name":"dnsmasq"}' > "$work/dns-service" && dns_listener ||
	die 'The DNS listeners failed verification after installation.'
manifest > "$work/after" || die 'Cannot verify installed packages.'
awk 'FILENAME == ARGV[1] { expected[$1] = $2; next }
	FILENAME == ARGV[2] { if ($2 == "-") delete expected[$1]; else expected[$1] = $2; next }
	{ if ($2 != expected[$1]) bad = 1; delete expected[$1] }
	END { for (n in expected) bad = 1; exit bad }' \
	"$work/before" "$work/allowed" "$work/after" || die 'Installed packages do not match the confirmed proposal.'
[ "$(awk '$1 == "selective-vpn" { print $2 }' "$work/after")" = "$version" ] || die 'The requested backend version was not installed.'
if [ -n "$luci_checksum" ]; then
	[ "$(awk '$1 == "luci-app-selective-vpn" { print $2 }' "$work/after")" = "$version" ] || die 'The requested LuCI version was not installed.'
fi
cp -p "$work/after" "$backup/installed"
rm "$backup/armed"
sync
armed=0
printf '%s\n' 'Installation completed. Configure routing before enabling it.'
if [ -n "$luci_checksum" ]; then
	printf '%s\n' 'Open Services > Selective VPN in LuCI.'
fi
