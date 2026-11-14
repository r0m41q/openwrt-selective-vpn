Run the tests from the repository root:

```sh
sh tests/run.sh
```

Requires Python 3. If BusyBox is installed, the tests also run under ash.

With Ruff installed, check Python lint:

```sh
ruff check .
ruff format --check .
```
