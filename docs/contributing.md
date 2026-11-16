# Contributing

Issues and small, focused pull requests are welcome. Include the OpenWrt release, package versions, resolver type, VPN mode and steps to reproduce. Remove credentials, private keys, public IPs and raw diagnostic captures before sharing logs.

Run `sh tests/run.sh`, `ruff check .` and `ruff format --check .` before submitting a code change. The tests use simulated router services; describe any real OpenWrt checks separately. See [building](building.md) for the pinned SDK package build and [router checks](integration.md) for live validation.
