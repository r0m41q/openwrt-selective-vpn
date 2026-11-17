Run the tests from the repository root:

```sh
sh tests/run.sh
```

Requires Python 3. If BusyBox is installed, the tests also run under ash.
Tests run in parallel, one job per CPU by default. To run only some of them:

```sh
sh tests/run.sh test_rules test_policy.PolicyTests
SVPN_TEST_JOBS=4 sh tests/run.sh
```

Node.js 18 or later runs the LuCI checks:

```sh
node --test tests/luci_test.cjs
```

With ucode and its fs and uloop modules installed:

```sh
SVPN_TEST_UCODE=ucode python3 -m unittest tests.test_rpc_ucode -v
```

With Ruff installed, check Python lint:

```sh
ruff check .
ruff format --check .
```
