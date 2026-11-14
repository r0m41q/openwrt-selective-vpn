import json
import os
from pathlib import Path
import re
import sys

from jsonfilter_fixture import query

root = Path(os.environ["test_root"])
command, *args = sys.argv[1:]


def emit(value):
    print(json.dumps(value))


def flag(name):
    return (root / name).exists()


def text(name):
    return (root / name).read_text()


def selected(kind, fallback):
    return (
        text("selected-" + kind).strip()
        if flag("selected-" + kind)
        else fallback
    )


def service(name, action, *rest):
    with (root / "calls").open("a") as stream:
        stream.write(" ".join([name, action, *rest]) + "\n")
    if flag(f"fail-{name}-{action}"):
        sys.exit(2)
    if name == "pbr":
        if action == "version":
            print(text("version"))
        elif action == "running":
            sys.exit(0 if flag("pbr-running") else 1)
        elif action == "reload":
            (root / "pbr-running").touch(mode=0o600)
            if flag("break-forwarding"):
                (root / "proc/sys/net/ipv4/ip_forward").write_text("0\n")
            if flag("change-wan"):
                (root / "routes4").write_text(
                    text("routes4").replace("203.0.113.1", "203.0.113.99")
                )
            if flag("alter-dhcp"):
                path = root / "config/dhcp"
                path.write_text(
                    path.read_text() + "config host\n option name 'later'\n"
                )
            if "resolver_set 'dnsmasq.nftset'" in text("config/pbr"):
                path = root / "config/dhcp"
                mount = "\tlist addnmount '/var/run/pbr.dnsmasq'\n"
                if mount not in path.read_text():
                    path.write_text(
                        path.read_text().replace(
                            "config dnsmasq\n", "config dnsmasq\n" + mount, 1
                        )
                    )
                snippet = ""
                for match in re.finditer(
                    r"option dest_addr '([^']+)'", text("config/pbr")
                ):
                    for value in match[1].split():
                        if re.search(r"[a-z]", value):
                            snippet += f"nftset=\
/{value}/4#inet#fw4#pbr_xcloud_vpn_4_dst_ip_console\n"
                (root / "pbr.dnsmasq").write_text(
                    snippet if not flag("no-snippet") else ""
                )
        elif action == "stop":
            (root / "pbr-running").unlink(missing_ok=True)
            if "resolver_set 'dnsmasq.nftset'" in text("config/pbr"):
                path = root / "config/dhcp"
                path.write_text(
                    path.read_text().replace(
                        "\tlist addnmount '/var/run/pbr.dnsmasq'\n", ""
                    )
                )
                (root / "pbr.dnsmasq").unlink(missing_ok=True)
    if name == "openvpn":
        if rest != ("xcloud_client",):
            raise ValueError("unscoped VPN mutation")
        path = root / "sysnet/tun_xc0"
        if action == "start" and not flag("no-vpn"):
            path.mkdir(parents=True, exist_ok=True)
            (path / "tun_flags").write_text("0x1001\n")
            (root / "vpn-running").touch(mode=0o600)
        if action == "stop":
            (root / "vpn-running").unlink(missing_ok=True)
            if path.exists():
                (path / "tun_flags").unlink(missing_ok=True)
                path.rmdir()


if command == "service":
    service(*args)
elif command == "fw4":
    sys.exit(1 if flag("bad-firewall") else 0)
elif command == "jsonfilter":
    query(args[1], args[3])
elif command == "ubus":
    _, _, _, obj, method, *payload = args
    if obj == "network.interface":
        print(text("live.json"))
    elif obj == "service":
        name = json.loads(payload[0])["name"]
        if name == "xcloud-bypass":
            emit(
                {
                    name: {
                        "instances": {
                            "recovery": {"running": not flag("no-supervisor")}
                        }
                    }
                }
            )
        elif name == "openvpn":
            client = selected("client", "xcloud_client")
            emit(
                {
                    name: {
                        "instances": {
                            client: {
                                "running": (
                                    flag("vpn-running")
                                    or flag("external-running")
                                ),
                                "pid": int(text("pid")),
                            }
                        }
                    }
                }
            )
        elif name == "pbr":
            errors = (
                [{"code": "errorFailedSetup"}] if flag("pbr-error") else []
            )
            emit(
                {
                    name: {
                        "instances": {
                            "main": {
                                "data": {
                                    "gateways": [{"name": "wan"}],
                                    "errors": errors,
                                }
                            }
                        }
                    }
                }
            )
        elif name == "dnsmasq":
            emit(
                {
                    name: {
                        "instances": {"cfg123": {"running": True, "pid": 123}}
                    }
                }
            )
    elif obj == "network" and method == "reload":
        with (root / "calls").open("a") as stream:
            stream.write("network reload\n")
    elif obj == "network.interface.xcloud_vpn" and method == "add_device":
        if json.loads(payload[0]) != {"name": "tun_xc0", "link-ext": True}:
            raise ValueError("unsafe attachment")
    elif obj == "network.interface.xcloud_vpn" and method == "status":
        emit({"up": True, "l3_device": "tun_xc0"})
    elif obj == "network.interface.vpnuser" and method == "status":
        emit({"up": True, "l3_device": "tun_user"})
    else:
        raise ValueError("unknown fixture ubus call")
elif command == "ip":
    if args[:3] == ["-4", "route", "get"]:
        print(f"{args[3]} dev br-lan src 192.168.8.1")
    elif args[:4] in (
        ["-4", "-o", "route", "show"],
        ["-6", "-o", "route", "show"],
    ):
        print(text("routes" + args[0][1:]), end="")
        if args[0] == "-4" and flag("vpn-running"):
            print(
                "10.9.0.0/24 dev tun_xc0 proto kernel scope link src 10.9.0.2"
            )
    elif args[:3] == ["-4", "route", "show"]:
        if not flag("no-pbr-route"):
            print("default via 10.9.0.1 dev " + selected("device", "tun_xc0"))
    elif args[:3] == ["-4", "rule", "show"]:
        print(
            "30000: from all fwmark 0x10000/0xff0000 lookup pbr_"
            + selected("interface", "xcloud_vpn")
        )
    elif args[:3] == ["-o", "link", "show"]:
        print(
            "5: "
            + selected("device", "tun_xc0")
            + ": <POINTOPOINT,UP,LOWER_UP>"
        )
    elif args[:4] == ["-4", "-o", "address", "show"]:
        if (flag("vpn-running") or flag("external-running")) and not flag(
            "no-address"
        ):
            tun = selected("device", "tun_xc0")
            print(f"5: {tun} inet 10.9.0.2/24 scope global {tun}")
    else:
        raise ValueError("unknown fixture ip call")
elif command == "nft":
    if flag("no-policies"):
        emit({"nftables": []})
    elif "sets" in args:
        emit(
            {
                "nftables": [
                    {"set": {"name": "pbr_xcloud_vpn_4_dst_ip_console"}}
                ]
            }
        )
    else:
        emit(
            {
                "nftables": [
                    {"rule": {"comment": label}}
                    for label in (
                        "Xbox console authentication",
                        "Browser xCloud authentication",
                        "Custom authentication destinations",
                    )
                    if {
                        "Xbox console authentication": "xcloud_console",
                        "Browser xCloud authentication": "xcloud_browser",
                        "Custom authentication destinations": "xcloud_custom",
                    }[label]
                    in text("config/pbr")
                ]
            }
        )
elif command == "dnsmasq":
    print("Dnsmasq version 2.93\nCompile time options: IPv6 DHCP nftset")
elif command == "ss":
    print(
        'udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=123,fd=5))'
    )
    print(
        'tcp LISTEN 0 32 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=123,fd=6))'
    )
else:
    raise ValueError("unknown fixture command")
