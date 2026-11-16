#!/usr/bin/env python3

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def fail(message):
    raise SystemExit(message)


def source_files(root, name):
    base = root / name
    if (base / "LICENSE").read_bytes() != (root / "LICENSE").read_bytes():
        fail(f"{name}: license differs from the repository license")
    files = {}
    if name == "selective-vpn":
        for source in (base / "files").rglob("*"):
            if source.is_file():
                files[source.relative_to(base / "files").as_posix()] = source
    else:
        for source in (base / "htdocs/luci-static/resources").rglob("*"):
            if source.is_file():
                if source.suffix != ".js":
                    fail(f"Unexpected LuCI source: {source}")
                relative = source.relative_to(
                    base / "htdocs/luci-static/resources"
                )
                files[f"www/luci-static/resources/{relative.as_posix()}"] = (
                    source
                )
        for source in (base / "root").rglob("*"):
            if source.is_file():
                if source.suffix != ".json" and source.name != "selective-vpn":
                    fail(f"Unexpected LuCI source: {source}")
                files[source.relative_to(base / "root").as_posix()] = source
    files[f"usr/share/licenses/{name}/LICENSE"] = base / "LICENSE"
    return files


def mode_for(path):
    if path == "etc/config/selective-vpn":
        return 0o600
    if path == "etc/init.d/selective-vpn" or path == "usr/bin/selective-vpn":
        return 0o755
    if path.startswith("usr/lib/selective-vpn/") and not path.endswith(
        (".sh", ".awk")
    ):
        return 0o755
    return 0o644


def check_removal(removal):
    if "selective-vpn uninstall before removing the package" not in removal:
        fail("Core package is missing its removal guard.")
    guard = removal.split("default_prerm\n", 1)[1]
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        pending = directory / "pending"
        service = directory / "service"
        calls = directory / "calls"
        uci = directory / "uci"
        uci.write_text('#!/bin/sh\n[ "$ACTIVE" = 1 ]\n')
        uci.chmod(0o755)
        service.write_text(f'#!/bin/sh\nprintf "%s\\n" "$1" >> "{calls}"\n')
        service.chmod(0o755)
        guard = guard.replace("/etc/selective-vpn/pending", str(pending))
        guard = guard.replace("/etc/init.d/selective-vpn", str(service))
        for active, upgrade, is_pending, code, expected in (
            ("0", "0", False, 0, []),
            ("1", "0", False, 1, ["enable", "start"]),
            ("0", "1", True, 1, ["start"]),
            ("0", "1", False, 0, []),
        ):
            pending.unlink(missing_ok=True)
            calls.unlink(missing_ok=True)
            if is_pending:
                pending.touch()
            environment = dict(os.environ)
            environment.update(
                PATH=f"{directory}:{os.environ['PATH']}",
                ACTIVE=active,
                PKG_UPGRADE=upgrade,
                IPKG_INSTROOT="",
            )
            result = subprocess.run(
                ["/bin/sh", "-c", guard],
                env=environment,
                capture_output=True,
                text=True,
            )
            observed = calls.read_text().splitlines() if calls.exists() else []
            if result.returncode != code or observed != expected:
                fail("Core package removal guard did not behave as expected.")


def inspect(apk, root, output, name, version):
    package = output / f"{name}-{version}.apk"
    result = subprocess.run(
        [str(apk), "adbdump", "--format", "json", str(package)],
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(result.stdout)
    info = data["info"]
    for field, expected in (
        ("name", name),
        ("version", version),
        ("arch", "noarch"),
        ("license", "MIT"),
        ("origin", f"feeds/base/{name}"),
    ):
        if info.get(field) != expected:
            fail(f"{name}: unexpected {field}: {info.get(field)}")

    expected = source_files(root, name)
    found = set()
    for directory in data["paths"]:
        prefix = directory.get("name", "")
        for entry in directory.get("files", []):
            path = "/".join(filter(None, (prefix, entry["name"])))
            if path.startswith("lib/apk/packages/"):
                suffix = path.removeprefix(f"lib/apk/packages/{name}")
                if suffix not in (".list", ".conffiles", ".conffiles_static"):
                    fail(f"{name}: unexpected package metadata: {path}")
                continue
            if path not in expected:
                fail(f"{name}: unexpected file: {path}")
            if path in found:
                fail(f"{name}: duplicate file: {path}")
            found.add(path)
            source = expected[path]
            if source.is_symlink():
                fail(f"{name}: symlink source: {path}")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            if entry.get("hash") != digest:
                fail(f"{name}: content differs from source: {path}")
            acl = entry.get("acl", {})
            if (acl.get("mode"), acl.get("user"), acl.get("group")) != (
                mode_for(path),
                "root",
                "root",
            ):
                fail(f"{name}: unexpected owner or mode: {path}")
    if found != expected.keys():
        fail(f"{name}: missing files: {sorted(expected.keys() - found)}")
    if name == "selective-vpn":
        removal = data.get("scripts", {}).get("pre-deinstall", "")
        check_removal(removal)
    print(f"Checked {name}: {len(found)} source files, no extra payload")


def main():
    if len(sys.argv) != 5:
        fail("Usage: check-apks.py SDK_APK PROJECT_ROOT OUTPUT_DIR VERSION")
    apk, root, output, version = map(Path, sys.argv[1:])
    for name in ("selective-vpn", "luci-app-selective-vpn"):
        inspect(apk, root, output, name, str(version))


if __name__ == "__main__":
    main()
