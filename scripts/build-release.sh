#!/bin/sh
set -eu
umask 022

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
sdk_name='openwrt-sdk-25.12.6-x86-64_gcc-14.3.0_musl.Linux-x86_64'
sdk_hash='1864152619092e781fa36a401960c8e9ae42d6a364c44ee5f0b197ca5f3c0fcc'
sdk_url="https://downloads.openwrt.org/releases/25.12.6/targets/x86/64/$sdk_name.tar.zst"
archive="$root/build/$sdk_name.tar.zst"
sdk="$root/build/sdk"
sign_key=''

case "$#" in
	0) ;;
	2) [ "$1" = '--sign-key' ] || exit 2; sign_key=$2 ;;
	*) printf '%s\n' 'Usage: sh scripts/build-release.sh [--sign-key PRIVATE_KEY]' >&2; exit 2 ;;
esac

mkdir -p "$root/build"
if [ ! -f "$archive" ]; then
	curl --fail --location --show-error --silent --retry 3 --output "$archive" "$sdk_url"
fi
printf '%s  %s\n' "$sdk_hash" "$archive" | sha256sum -c -
if [ ! -x "$sdk/staging_dir/host/bin/apk" ] ||
   [ "$(cat "$sdk/.selective-vpn-sdk-hash" 2>/dev/null || :)" != "$sdk_hash" ]; then
	rm -rf "$sdk"
	mkdir -p "$sdk"
	tar --zstd -xf "$archive" -C "$sdk" --strip-components=1
	printf '%s\n' "$sdk_hash" > "$sdk/.selective-vpn-sdk-hash"
fi

apk="$sdk/staging_dir/host/bin/apk"
for name in selective-vpn luci-app-selective-vpn; do
	rm -rf "$sdk/package/$name"
	cp -a "$root/$name" "$sdk/package/$name"
done

make -C "$sdk" defconfig > "$root/build/defconfig.log" 2>&1
for name in selective-vpn luci-app-selective-vpn; do
	(cd "$sdk" && make -C "package/$name" TOPDIR="$sdk" clean) > "$root/build/$name-clean.log" 2>&1
	(cd "$sdk" && make -C "package/$name" TOPDIR="$sdk" V=s) > "$root/build/$name.log" 2>&1
done

version=$(awk -F:= '/^PKG_VERSION:=/ { version = $2 } /^PKG_RELEASE:=/ { release = $2 } END { print version "-r" release }' "$root/selective-vpn/Makefile")
other=$(awk -F:= '/^PKG_VERSION:=/ { version = $2 } /^PKG_RELEASE:=/ { release = $2 } END { print version "-r" release }' "$root/luci-app-selective-vpn/Makefile")
[ "$version" = "$other" ] || { printf '%s\n' 'Package versions differ.' >&2; exit 1; }

if [ -n "$sign_key" ]; then
	[ -f "$sign_key" ] || { printf '%s\n' 'Signing key was not found.' >&2; exit 1; }
	output="$root/dist/v$version"
else
	output="$root/build/release-check/v$version"
fi
mkdir -p "$output"
for name in selective-vpn luci-app-selective-vpn; do
	source="$sdk/bin/packages/x86_64/base/$name-$version.apk"
	[ -f "$source" ] || { printf 'Missing APK: %s\n' "$source" >&2; exit 1; }
	cp "$source" "$output/$name-$version.apk"
done

if [ -n "$sign_key" ]; then
	for name in selective-vpn luci-app-selective-vpn; do
		"$apk" --allow-untrusted adbsign --sign-key "$sign_key" "$output/$name-$version.apk"
	done
	openssl pkey -in "$sign_key" -pubout -out "$output/selective-vpn.pub.pem"
	chmod 644 "$output/selective-vpn.pub.pem"
	keys="$root/build/release-keys"
	mkdir -p "$keys"
	cp "$output/selective-vpn.pub.pem" "$keys/selective-vpn.pem"
	for name in selective-vpn luci-app-selective-vpn; do
		"$apk" --keys-dir "$keys" verify "$output/$name-$version.apk"
	done
	openssl pkey -pubin -in "$output/selective-vpn.pub.pem" -outform DER | sha256sum | cut -d ' ' -f 1 > "$output/KEY-FINGERPRINT"
fi

python3 "$root/scripts/check-apks.py" "$apk" "$root" "$output" "$version"
cp "$root/install.sh" "$root/LICENSE" "$output/"
if [ -n "$sign_key" ]; then
	(cd "$output" && sha256sum "selective-vpn-$version.apk" "luci-app-selective-vpn-$version.apk" install.sh LICENSE selective-vpn.pub.pem KEY-FINGERPRINT > SHA256SUMS)
else
	(cd "$output" && sha256sum "selective-vpn-$version.apk" "luci-app-selective-vpn-$version.apk" install.sh LICENSE > SHA256SUMS)
fi
chmod 644 "$output"/*.apk "$output/install.sh" "$output/LICENSE" "$output/SHA256SUMS"
printf 'Built %s\n' "$output"
