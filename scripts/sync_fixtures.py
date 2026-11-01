"""Copies the shared conformance fixtures into tests/fixtures.

The fixtures are the executable half of the contract every ZevAuth
server library implements:
https://github.com/zevop/zevauth-sdk/tree/main/spec/fixtures

They are vendored, not fetched at test time, so the test suite runs
offline and a change upstream reaches this library only through a
reviewed commit. Run this after the contract changes:

    python scripts/sync_fixtures.py ../zevauth-sdk/spec/fixtures
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

FILES = [
    "api-errors.json",
    "bearer.json",
    "bridge.json",
    "discovery.json",
    "jwks-rotated.json",
    "jwks.json",
    "tokens.json",
    "webhooks.json",
]


def main() -> int:
    source = Path(sys.argv[1] if len(sys.argv) > 1 else "../zevauth-sdk/spec/fixtures").resolve()
    target = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
    missing = [name for name in FILES if not (source / name).is_file()]
    if missing:
        print(f"Not found in {source}: {', '.join(missing)}", file=sys.stderr)
        return 1
    target.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        shutil.copyfile(source / name, target / name)
        print(f"  {name}")
    print(f"Copied {len(FILES)} fixtures to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
