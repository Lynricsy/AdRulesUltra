from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

CONFIG_TEMPLATE = """mixed-port: 17890
allow-lan: false
mode: rule
log-level: error
rule-providers:
  ads_domain:
    type: file
    behavior: domain
    format: mrs
    path: ./ruleset/adrules_ultra_ads.mrs
  ads_ipcidr:
    type: file
    behavior: ipcidr
    format: mrs
    path: ./ruleset/adrules_ultra_ads_ipcidr.mrs
  allow_domain:
    type: file
    behavior: domain
    format: mrs
    path: ./ruleset/adrules_ultra_allow.mrs
  allow_ipcidr:
    type: file
    behavior: ipcidr
    format: mrs
    path: ./ruleset/adrules_ultra_allow_ipcidr.mrs
  malware_domain:
    type: file
    behavior: domain
    format: mrs
    path: ./ruleset/adrules_ultra_malware.mrs
  malware_ipcidr:
    type: file
    behavior: ipcidr
    format: mrs
    path: ./ruleset/adrules_ultra_malware_ipcidr.mrs
rules:
  - RULE-SET,allow_domain,PASS
  - RULE-SET,allow_ipcidr,PASS,no-resolve
  - RULE-SET,ads_domain,REJECT
  - RULE-SET,ads_ipcidr,REJECT,no-resolve
  - RULE-SET,malware_domain,REJECT
  - RULE-SET,malware_ipcidr,REJECT,no-resolve
  - MATCH,DIRECT
"""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Load all published MRS files with mihomo -t.")
    _ = parser.add_argument("--dist", type=Path, required=True)
    _ = parser.add_argument("--mihomo", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    dist = cast("Path", args.dist)
    mihomo = cast("Path", args.mihomo)
    required = [
        "adrules_ultra_ads.mrs",
        "adrules_ultra_ads_ipcidr.mrs",
        "adrules_ultra_allow.mrs",
        "adrules_ultra_allow_ipcidr.mrs",
        "adrules_ultra_malware.mrs",
        "adrules_ultra_malware_ipcidr.mrs",
    ]
    for name in required:
        path = dist / name
        if not path.is_file() or path.stat().st_size == 0:
            print(f"missing mrs asset: {path}", file=sys.stderr)
            return 1

    home = Path(tempfile.mkdtemp(prefix="mihomo-validate-"))
    try:
        ruleset_dir = home / "ruleset"
        _ = ruleset_dir.mkdir(parents=True)
        for name in required:
            _ = shutil.copy2(dist / name, ruleset_dir / name)
        config_path = home / "config.yaml"
        _ = config_path.write_text(CONFIG_TEMPLATE, encoding="utf-8")
        completed = subprocess.run(  # noqa: S603 - trusted local mihomo binary
            [str(mihomo), "-d", str(home), "-t", "-f", str(config_path)],
            check=False,
            text=True,
            capture_output=True,
        )
        if completed.stdout:
            print(completed.stdout, end="")
        if completed.stderr:
            print(completed.stderr, end="", file=sys.stderr)
        if completed.returncode != 0:
            return completed.returncode
    finally:
        shutil.rmtree(home, ignore_errors=True)
    print("all mrs assets loaded successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
