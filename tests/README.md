Run the tests from the repository root:

```sh
sh tests/run.sh
```

Requires Python 3. If BusyBox is installed, the tests also run under ash.
Node.js 18 or later runs the LuCI checks:

```sh
node --test tests/luci_test.cjs
```

With ucode and its fs and uloop modules installed:

```sh
XCB_TEST_UCODE=ucode python3 -m unittest tests.test_rpc_ucode -v
```

With Ruff installed, check Python lint:

```sh
ruff check .
ruff format --check .
```
