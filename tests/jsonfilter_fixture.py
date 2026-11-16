import json
from pathlib import Path
import re
import sys


def query(path, expression):
    if not expression.startswith("@"):
        raise ValueError("invalid fixture query")
    values = [json.loads(Path(path).read_text())]
    position = 1
    while position < len(expression):
        match = re.match(
            r"\.([a-zA-Z0-9_]+|\*)|\[(\d+|\*|'[^']+')\]", expression[position:]
        )
        if not match:
            raise ValueError("unsupported fixture query")
        key = match[1] if match[1] is not None else match[2]
        if key.startswith("'"):
            key = key[1:-1]
        result = []
        for value in values:
            if key == "*" and isinstance(value, list):
                result.extend(value)
            elif key == "*" and isinstance(value, dict):
                result.extend(value.values())
            elif (
                isinstance(value, list)
                and key.isdigit()
                and int(key) < len(value)
            ):
                result.append(value[int(key)])
            elif isinstance(value, dict) and key in value:
                result.append(value[key])
        values = result
        position += len(match[0])
    for value in values:
        if isinstance(value, str):
            print(value)
        else:
            print(json.dumps(value))
    return bool(values)


if __name__ == "__main__":
    try:
        query(*sys.argv[1:])
    except (ValueError, TypeError, OSError):
        sys.exit(1)
