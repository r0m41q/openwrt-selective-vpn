import ipaddress
import os
from pathlib import Path
import shlex
import subprocess
import unittest


LIBRARY = (
    Path(__file__).resolve().parents[1]
    / "xcloud-bypass/files/usr/lib/xcloud-bypass"
)
SHELL = shlex.split(os.environ.get("XCB_TEST_SHELL", "/bin/sh"))


class ValidationTests(unittest.TestCase):
    def invoke(self, name, *values):
        return subprocess.run(
            [
                *SHELL,
                "-eu",
                "-c",
                '. "$1/common.sh"; . "$1/validate.sh"; shift; "$@"',
                "validator",
                str(LIBRARY),
                "xcb_" + name,
                *values,
            ],
            capture_output=True,
            timeout=5,
        )

    def check(self, name, values, expected=0, output=b""):
        result = self.invoke(name, *values)
        self.assertEqual(result.returncode, expected, result.stderr.decode())
        self.assertEqual(result.stdout, output)
        self.assertEqual(result.stderr, b"")

    def cases(self, name, valid, invalid):
        for value in valid:
            with self.subTest(validator=name, value=value):
                self.check(name, (value,))
        for value in invalid:
            with self.subTest(validator=name, value=value):
                self.check(name, (value,), expected=1)

    def test_unsigned_numbers(self):
        for value in ("0", "1", "255"):
            self.check("valid_uint", (value, "255"))
        for value in ("", "256", "01", "00", "-1", "+1", "1e2", " 1", "1 ", "1\n", "9" * 80):
            self.check("valid_uint", (value, "255"), expected=1)
        for limit in ("", "-1", "01", "1+1", "9999999999"):
            self.check("valid_uint", ("1", limit), expected=1)

    def test_booleans(self):
        self.cases("valid_bool", ["0", "1"], ["", "true", "false", "yes", "2", "01", "1\n"])

    def test_ipv4(self):
        self.cases(
            "valid_ipv4",
            ["0.0.0.0", "255.255.255.255", "192.168.1.2", "51.12.31.0"],
            ["", "1", "127.1", "1.2.3", "1.2.3.4.5", "256.0.0.1", "1..2.3",
             ".1.2.3.4", "1.2.3.4.", "01.2.3.4", "1.2.3.004", "-1.2.3.4",
             "1.2.3.4/24", "::1", " 1.2.3.4", "1.2.3.4\n", "١.2.3.4"],
        )

    def test_cidr(self):
        self.cases(
            "valid_cidr",
            ["0.0.0.0/0", "192.168.1.42/24", "192.168.1.42/32"],
            ["", "192.168.1.0", "192.168.1.0/", "192.168.1.0/33",
             "192.168.1.0/-1", "192.168.1.0/024", "192.168.1.0/24/1",
             "192.168.1.0/255.255.255.0", "256.168.1.0/24"],
        )

    def test_subnet_boundaries(self):
        for address in ("192.168.1.42", "10.16.128.1", "255.255.255.255"):
            for prefix in range(33):
                network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
                with self.subTest(network=str(network)):
                    self.check("valid_subnet", (str(network),))
                    if network.num_addresses > 1:
                        host = f"{network.network_address + 1}/{prefix}"
                        self.check("valid_subnet", (host,), expected=1)
        for value in ("", "10.0.0.0/33", "10.0.0.0/8/1", "10.0.0.0/08"):
            self.check("valid_subnet", (value,), expected=1)

    def test_domains(self):
        self.cases(
            "valid_domain",
            ["xsts.auth.xboxlive.com", "EXAMPLE.COM", "a-b.example", "xn--bcher-kva.example",
             "a" * 63 + ".example", ".".join(["a" * 63] * 3 + ["a" * 61])],
            ["", "xbox", ".example.com", "example.com.", "a..example", "-a.example",
             "a-.example", "_srv.example", "*.example", "https://example.com",
             "example.com:443", "192.168.1.2", "999.999.999.999", "a.123",
             "bücher.example", "a" * 64 + ".example", ".".join(["a" * 63] * 4)],
        )

    def test_hostnames(self):
        self.cases(
            "valid_hostname",
            ["Xbox", "xbox-series-x", "xbox.lan", "123x"],
            ["", "123", "192.168.1.1", "bad_name", "xbox/../../etc", "xbox.local.", "xbox\r"],
        )

    def test_identifiers(self):
        self.cases(
            "valid_identifier",
            ["lan", "_internal", "xcloud_console", "a" * 63],
            ["", "1lan", "lan-1", "lan.wan", "../lan", "a" * 64, "é"],
        )
        self.cases(
            "reserved_identifier",
            ["xcloud_console", "xcloud_1"],
            ["xcloud_", "xcloud", "console", "Xcloud_console", "xcloud_../../etc"],
        )
        self.cases("valid_interface", ["tun0", "xcloud_vpn", "a" * 15], ["", "a" * 16, "tun/0", "@tun0"])

    def test_devices_and_destinations(self):
        self.cases("valid_device", ["Xbox", "192.168.1.42", "xbox.lan"],
                   ["", "192.168.1.42/24", "256.168.1.1", "*", "::1", "01.2.3.4"])
        self.cases("valid_destination", ["20.201.200.49", "51.12.31.0/32", "example.com"],
                   ["", "xbox", "https://example.com", "1.2.3.4/99", "@wan"])

    def test_byte_limits(self):
        for value, limit, status in (("", "0", 0), ("a", "0", 1), ("abc", "3", 0),
                                     ("abc", "2", 1), ("é", "2", 0), ("é", "1", 1),
                                     ("a" * 32768, "32768", 0), ("a" * 32769, "32768", 1)):
            self.check("valid_size", (value, limit), expected=status)

    def test_lists(self):
        cases = [
            ("domain", "EXAMPLE.COM example.com\nother.example\tEXAMPLE.COM", b"example.com\nother.example\n"),
            ("device", "192.168.1.42\nXbox\txbox", b"192.168.1.42\nxbox\n"),
            ("ipv4", "1.2.3.4 1.2.3.4 5.6.7.8", b"1.2.3.4\n5.6.7.8\n"),
            ("subnet", "10.0.0.0/8 192.168.1.0/24", b"10.0.0.0/8\n192.168.1.0/24\n"),
            ("identifier", "LAN lan LAN", b"LAN\nlan\n"),
            ("hostname", "Xbox xbox.local", b"xbox\nxbox.local\n"),
            ("destination", "EXAMPLE.COM 1.2.3.4/32", b"example.com\n1.2.3.4/32\n"),
            ("domain", " \n\t", b""),
        ]
        for kind, value, output in cases:
            with self.subTest(kind=kind, value=value):
                self.check("normalize_list", (kind, value), output=output)
        self.check("normalize_list", ("ipv4", " ".join(["1.2.3.4"] * 64)), output=b"1.2.3.4\n")
        self.check("normalize_list", ("domain", " " * 4096))
        for kind, value in (("domain", "good.example bad_name"), ("device", "xbox 256.0.0.1"),
                            ("subnet", "10.0.0.1/8"), ("device", " ".join(["xbox"] * 65)),
                            ("domain", " " * 4097), ("unknown", ""), ("ipv4", "1.2.3.4\r")):
            self.check("normalize_list", (kind, value), expected=1)

    def test_empty_devices_are_distinct_from_invalid_devices(self):
        for value in ("", " ", "\t\n"):
            self.check("normalize_devices", (value,), expected=3)
        for value in ("999.0.0.1", "xbox invalid/name", "*", "xbox;reboot"):
            self.check("normalize_devices", (value,), expected=1)
        self.check("normalize_devices", ("Xbox 192.168.1.42 xbox",), output=b"xbox\n192.168.1.42\n")

    def test_untrusted_strings_are_not_executed_or_echoed(self):
        attacks = ["$(printf INJECTED)", "`printf INJECTED`", "x; printf INJECTED", "x\nreboot",
                   "../../etc/shadow", "x' || printf INJECTED #", 'x"; printf INJECTED',
                   "*", "[a-z]", "--help", "x\x1b[31m"]
        for attack in attacks:
            for validator in ("valid_ipv4", "valid_domain", "valid_hostname", "valid_identifier"):
                with self.subTest(validator=validator, attack=attack):
                    self.check(validator, (attack,), expected=1)
            self.check("normalize_list", ("domain", attack), expected=1)
        self.check("normalize_list", ("$(printf INJECTED)", "xbox"), expected=1)

    def test_argument_counts(self):
        single = ("valid_bool", "valid_ipv4", "valid_cidr", "valid_subnet", "valid_domain",
                  "valid_hostname", "valid_identifier", "reserved_identifier", "valid_interface",
                  "valid_device", "valid_destination", "normalize_devices")
        for name in single:
            self.check(name, (), expected=1)
            self.check(name, ("xbox", "extra"), expected=1)
        for name in ("valid_uint", "valid_size", "valid_dns_name", "normalize_list"):
            for values in ((), ("1",), ("1", "1", "1")):
                self.check(name, values, expected=1)


if __name__ == "__main__":
    unittest.main()
