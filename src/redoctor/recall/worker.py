"""Isolated worker for timing one regex match."""

import json
import re
import sys
import time


def main() -> None:
    """Read one match request from stdin and write its timing as JSON."""
    try:
        payload = json.load(sys.stdin)
        regex = re.compile(payload["pattern"], payload.get("flags", 0))
        start = time.perf_counter()
        regex.search(payload["string"])
        result = {"elapsed": time.perf_counter() - start}
    except re.error as error:
        result = {"error": f"Invalid regex: {error}"}
    except (KeyError, TypeError, ValueError) as error:
        result = {"error": f"Invalid recall request: {error}"}
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
