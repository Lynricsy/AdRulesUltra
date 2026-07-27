from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import cast

from scripts.ruleset_mrs import ensure_ipcidr_mrs_from_text


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write empty MRS for comment-only ipcidr text, else signal convert.")
    _ = parser.add_argument("--text", type=Path, required=True)
    _ = parser.add_argument("--mrs", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    text_path = cast("Path", args.text)
    mrs_path = cast("Path", args.mrs)
    mode = ensure_ipcidr_mrs_from_text(text_path, mrs_path)
    if mode == "used":
        return 10
    print(f"{text_path.name}: empty mrs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
