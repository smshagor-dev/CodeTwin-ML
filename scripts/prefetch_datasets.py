from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "ml"))

from codetwin_ml.datasets import (  # noqa: E402
    DatasetError,
    prefetch_action,
    prefetch_all,
    prefetch_dataset,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prefetch pinned CodeTwin ML datasets into the local cache."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--all", action="store_true", help="Download every catalog dataset.")
    target.add_argument("--action", help="Download datasets routed to one CodeTwin action.")
    target.add_argument("--dataset", help="Download one dataset by catalog id.")
    parser.add_argument(
        "--accept-license",
        action="append",
        default=[],
        metavar="LICENSE",
        help="Accept a required upstream license identifier (repeatable).",
    )
    parser.add_argument("--cache-dir", type=Path, help="Override datasets/cache.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    kwargs = {
        "accepted_licenses": args.accept_license,
        "cache_root": args.cache_dir,
    }
    try:
        if args.all:
            result = prefetch_all(**kwargs)
        elif args.action:
            result = prefetch_action(args.action, **kwargs)
        else:
            result = prefetch_dataset(args.dataset, **kwargs)
    except DatasetError as error:
        print(f"dataset prefetch failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
