import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

from jsonfilter_fixture import query

root = Path(os.environ["test_root"])
command, *args = sys.argv[1:]


def flag(name):
    return (root / name).exists()


def load():
    return json.loads((root / "packages.json").read_text())


def record(*values):
    with (root / "calls").open("a") as stream:
        stream.write(json.dumps(values) + "\n")


# like a mips router, where apk --print-arch says mipsel
def feed_arch():
    return "x86_64" if flag("bad-arch") else "mipsel_24kc"


def package(name, version):
    return {
        "info": {
            "name": name,
            "version": version,
            "arch": "noarch" if "selective-vpn" in name else feed_arch(),
            "installed-size": 4096,
        }
    }


KEY = "-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n"


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


# the checksum list of one release, like scripts/build-release.sh writes it
def release_sums(version):
    lines = []
    for name in ("selective-vpn", "luci-app-selective-vpn"):
        text = json.dumps(package(name, version))
        if flag("bad-checksum") and name == "selective-vpn":
            text += " "
        lines.append(f"{digest(text)}  {name}-{version}.apk")
    lines.append(f"{digest(KEY)}  selective-vpn.pub.pem")
    lines.append(f"{digest('install')}  install.sh")
    return "\n".join(lines) + "\n"


def emit(value):
    print(json.dumps(value))


# newest builds in the feed; the router image may carry older ones
FEED = {
    "dnsmasq": "2.93-r3",
    "dnsmasq-full": "2.93-r2",
    "pbr": "1.2.2-r20",
    "luci": "25.12-r1",
    "luci-base": "25.12-r1",
    "curl": "25.12-r1",
    "ca-bundle": "25.12-r1",
}


def dns_service():
    return {"dnsmasq": {"instances": {"main": {"running": True, "pid": 42}}}}


def solve(arguments):
    before = load()
    after = before.copy()
    files = [Path(arg) for arg in arguments if arg.endswith(".apk")]
    requested = {}
    for path in files:
        info = json.loads(path.read_text())["info"]
        requested[info["name"]] = info["version"]
    recovery = not any("/new/" in str(path) for path in files)
    if "dnsmasq-full" in arguments:
        requested["dnsmasq-full"] = "2.93-r2"
        recovery = False
    for name in ("luci", "curl", "ca-bundle"):
        if name in arguments:
            requested[name] = "25.12-r1"
            recovery = False
    if "luci" in requested:
        requested["luci-base"] = "25.12-r1"
    if recovery:
        constraints = (root / "etc/apk/world").read_text().splitlines()
        names = {re.split(r"[=@~<>]", value)[0] for value in constraints}
        for name in list(after):
            # dnsmasq-full stays while it provides dnsmasq
            if name not in names and name in {
                "selective-vpn",
                "luci-app-selective-vpn",
            }:
                del after[name]
        for arg in arguments:
            if "=" in arg and not arg.startswith("--"):
                name, version = arg.split("=", 1)
                requested[name] = version
    elif "selective-vpn" in requested:
        requested.setdefault("pbr", "1.2.2-r20")
    if "dnsmasq-full" in requested:
        after.pop("dnsmasq", None)
        after.pop("dnsmasq-dhcpv6", None)
    # dnsmasq-full provides dnsmasq, so only a conflict replaces it
    for name in ("dnsmasq", "dnsmasq-dhcpv6", "dnsmasq-full"):
        if "!" + name in arguments:
            after.pop(name, None)
            requested.pop(name, None)
    if "dnsmasq-full" in after:
        requested.pop("dnsmasq", None)
    after.update(requested)
    if flag("unrelated-upgrade") and not recovery:
        after["uci"] = "2-r1"
    actions = []
    for name in sorted(before.keys() | after.keys()):
        old, new = before.get(name), after.get(name)
        if old == new:
            continue
        if new is None:
            action, versions = "Purging", old
        elif old is None:
            action, versions = "Installing", new
        else:
            action, versions = "Upgrading", f"{old} -> {new}"
        actions.append((action, name, versions))
    # real apk pads the step number, as in "( 1/12)"
    width = len(str(len(actions)))
    for index, (action, name, versions) in enumerate(actions, 1):
        step = f"({index:>{width}}/{len(actions)})"
        print(f"{step} {action} {name} ({versions})")
    print("OK: 20 MiB in 20 packages")
    return after, recovery, requested


if command == "apk":
    assert "--allow-untrusted" not in args
    assert "--no-check-certificate" not in args
    assert os.environ["APK_CONFIG"] == "/dev/null"
    if args == ["--version"]:
        print("apk-tools 3.0.5, compiled for x86_64")
        sys.exit()
    if args == ["--print-arch"]:
        print("mipsel")
        sys.exit()
    operation_index = next(
        i
        for i, arg in enumerate(args)
        if arg in {"list", "update", "verify", "adbdump", "cache", "add"}
    )
    operation = args[operation_index]
    start = operation_index + 1
    params = args[start:]
    record("apk", *args)
    if operation == "list":
        for name, version in sorted(load().items()):
            print(name, version)
    elif operation == "update":
        if flag("bad-repositories"):
            sys.exit(1)
        cache = Path(args[args.index("--cache-dir") + 1])
        (cache / "APKINDEX.0123abcd.tar.gz").write_text("index\n")
    elif operation == "verify":
        assert "--no-allow-untrusted" not in args
        assert "--check-certificate" in args
        # feed packages are unsigned; only the signed index trusts them
        assert "/cache/" not in params[-1]
        if "selective-vpn-" in Path(params[-1]).name:
            keys = Path(args[args.index("--keys-dir") + 1])
            assert (keys / "selective-vpn.pem").read_text() == KEY
        sys.exit(1 if flag("bad-signature") else 0)
    elif operation == "adbdump":
        data = json.loads(Path(params[-1]).read_text())
        if flag("huge-package"):
            data["info"]["installed-size"] = 100_000_000
        emit(data)
    elif operation == "cache":
        assert params[0] == "download"
        names = params[1:]
        # an installed package is only fetched with --upgrade
        if names[0] == "--upgrade":
            names = names[1:]
        else:
            assert not set(names) & set(load())
        if flag("missing-old") and names == ["dnsmasq"]:
            sys.exit(1)
        cache = Path(args[args.index("--cache-dir") + 1])
        for name in names:
            version = FEED.get(name, "1-r1")
            path = cache / f"{name}-{version}.89abcdef.apk"
            path.write_text(json.dumps(package(name, version)))
    elif operation == "add":
        if flag("solver-failure"):
            sys.exit(1)
        after, recovery, requested = solve(params)
        if "--simulate" not in params:
            assert "--no-network" in args
            record("mutation", "recovery" if recovery else "install")
            (root / "packages.json").write_text(json.dumps(after))
            world = root / "etc/apk/world"
            lines = world.read_text().splitlines()
            explicit_names = set()
            for argument in params:
                if argument.endswith(".apk"):
                    explicit_names.add(
                        json.loads(Path(argument).read_text())["info"]["name"]
                    )
                elif "=" in argument:
                    explicit_names.add(argument.split("=", 1)[0])
            for name, version in requested.items():
                if name not in explicit_names:
                    continue
                lines = [
                    line
                    for line in lines
                    if re.split(r"[=@~<>]", line)[0] != name
                ]
                lines.append(f"{name}={version}")
            world.write_text("\n".join(sorted(lines)) + "\n")
            if not recovery:
                path = root / "etc/config/selective-vpn"
                if not path.exists():
                    path.write_text(
                        "config settings 'main'\n option enabled '0'\n"
                    )
                if flag("edit-during-install"):
                    with (root / "etc/config/dhcp").open("a") as stream:
                        stream.write("# package migration\n")
                if flag("interrupt-install"):
                    (root / "mutated").touch()
                    while not flag("release-apk"):
                        time.sleep(0.02)
                if flag("fail-install"):
                    sys.exit(1)
elif command == "curl":
    assert args[0] == "--disable"
    assert args[args.index("--proto") + 1] == "=https"
    assert args[args.index("--proto-redir") + 1] == "=https"
    assert "--insecure" not in args
    record("curl", *args)
    if flag("download-failure"):
        sys.exit(1)
    url = args[-1]
    name = url.rsplit("/", 1)[1]
    path = Path(args[args.index("--output") + 1])
    if name == "SHA256SUMS":
        latest = "/releases/latest/download/" in url
        version = "0.1.0-r1" if latest else url.split("/")[-2][1:]
        path.write_text(release_sums(version))
    elif name == "selective-vpn.pub.pem":
        path.write_text(KEY)
    else:
        match = re.fullmatch(r"(.+)-(\d+\.\d+\.\d+-r\d+)\.apk", name)
        assert match
        data = package(*match.groups())
        if flag("wrong-metadata"):
            data["info"]["name"] = "other-app"
        path.write_text(json.dumps(data))
elif command == "jsonfilter":
    sys.exit(0 if query(args[1], args[3].replace('"', "'")) else 1)
elif command == "ubus":
    if args[1:3] == ["system", "board"]:
        emit(
            {
                "release": {
                    "distribution": "OpenWrt",
                    "version": "26.12.0" if flag("unsupported") else "25.12.6",
                }
            }
        )
    else:
        emit(dns_service())
elif command == "uci":
    if args[1] == "export":
        print((root / "etc/config/dhcp").read_text())
    elif args[1] == "changes":
        # real uci fails for a config that does not exist
        if not (root / "etc/config" / args[2]).exists():
            sys.exit(1)
        if flag("unsaved-edits"):
            print("dhcp.lan.ignore='1'")
    elif args[1] == "get":
        print("1" if flag("enabled") else "0")
elif command == "dnsmasq":
    packages = load()
    feature = "nftset" if "dnsmasq-full" in packages else "no-nftset"
    if flag("bad-full-features"):
        feature = "no-nftset"
    print(f"Dnsmasq version 2.93\nCompile time options: IPv6 {feature}")
elif command == "sleep":
    pass
elif command == "nslookup":
    record("dns-probe")
    if flag("interrupt-check") and "dnsmasq-full" in load():
        (root / "checked").touch()
        while flag("interrupt-check"):
            time.sleep(0.02)
    if flag("bad-dns"):
        sys.exit(1)
    if flag("fail-new-dns") and "dnsmasq-full" in load():
        if flag("late-edit"):
            (root / "etc/config/firewall").write_text("# user edit\n")
        sys.exit(1)
elif command == "service":
    record("service", *args)
elif command == "df":
    print("Filesystem 1024-blocks Used Available Capacity Mounted on")
    free = 10 if flag("low-space") else 65536
    print(f"overlay 131072 2048 {free} 2% /")
elif command == "stat":
    import subprocess

    result = subprocess.run(["/usr/bin/stat", *args], capture_output=True)
    if result.returncode:
        sys.exit(result.returncode)
    text = result.stdout.decode().strip()
    if args[1] in {"%u %h", "%u %a"}:
        text = "0 " + text.split(" ", 1)[1]
    print(text)
    sys.exit(result.returncode)
elif command == "openssl":
    sys.stdout.write("fixture public key")
elif command == "id":
    print("1000" if flag("nonroot") else "0")
else:
    raise ValueError(command)
