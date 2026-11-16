Run the tests from the repository root:

```sh
sh tests/run.sh
```

Requires Python 3. If BusyBox is installed, the tests also run under ash.

With ucode and its fs and uloop modules installed:

```sh
XCB_TEST_UCODE=ucode python3 -m unittest tests.test_rpc_ucode -v
```

With Ruff installed, check Python lint:

```sh
ruff check .
ruff format --check .
```
