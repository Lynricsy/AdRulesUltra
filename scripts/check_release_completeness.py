from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import cast

from scripts.ruleset_stats import expected_release_assets, release_assets_complete


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check whether a GitHub release already matches local artifacts.")
    _ = parser.add_argument("--repo", required=True)
    _ = parser.add_argument("--tag", required=True)
    _ = parser.add_argument("--local-checksum", type=Path, required=True)
    _ = parser.add_argument("--remote-checksum", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    repo = cast("str", args.repo)
    tag = cast("str", args.tag)
    local_checksum_path = cast("Path", args.local_checksum)
    remote_checksum_path = cast("Path", args.remote_checksum)

    local_checksum = local_checksum_path.read_text(encoding="utf-8")
    remote_checksum = remote_checksum_path.read_text(encoding="utf-8")
    assets_raw = subprocess.check_output(  # noqa: S603 - trusted gh CLI with controlled args
        ["gh", "release", "view", tag, "--repo", repo, "--json", "assets"],  # noqa: S607 - gh is on PATH in CI
        text=True,
    )
    assets_payload = cast("dict[str, list[dict[str, str]]]", json.loads(assets_raw))
    remote_names = {asset["name"] for asset in assets_payload["assets"]}
    if release_assets_complete(
        local_checksum_text=local_checksum,
        remote_checksum_text=remote_checksum,
        remote_asset_names=remote_names,
    ):
        print("existing release is complete; skip publish")
        return 0

    print("existing release is incomplete or stale; delete and rebuild")
    print("remote assets:")
    print("\n".join(sorted(remote_names)))
    print("expected assets:")
    print("\n".join(sorted(expected_release_assets(local_checksum))))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
