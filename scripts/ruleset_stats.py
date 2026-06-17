from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypedDict

from scripts.ruleset_core import OUTPUT_PREFIX
from scripts.ruleset_types import RuleKind

STATS_FILE: Final[str] = "stats.json"
ONE_THOUSAND: Final[int] = 1_000
TEN_THOUSAND: Final[int] = 10_000
ONE_MILLION: Final[int] = ONE_THOUSAND * ONE_THOUSAND
TEN_MILLION: Final[int] = 10 * ONE_MILLION
ONE_KIB: Final[int] = 1024
ONE_MIB: Final[int] = ONE_KIB * 1024
ONE_GIB: Final[int] = ONE_MIB * 1024


class RuleStatPayload(TypedDict):
    domains: int
    ipcidrs: int
    total: int
    domains_display: str
    ipcidrs_display: str
    total_display: str


class FileStatPayload(TypedDict):
    bytes: int
    display: str


class StatsPayload(TypedDict):
    schema_version: int
    rules: dict[str, RuleStatPayload]
    totals: RuleStatPayload
    mrs: dict[str, FileStatPayload]
    badges: dict[str, str]


@dataclass(frozen=True, slots=True)
class StatsArgs:
    output: Path


def build_stats_payload(output_dir: Path) -> StatsPayload:
    rules: dict[str, RuleStatPayload] = {}
    mrs: dict[str, FileStatPayload] = {}
    total_domains = 0
    total_ipcidrs = 0

    for kind in RuleKind:
        domain_count = count_lines(output_dir / f"{OUTPUT_PREFIX}_{kind.value}.txt")
        ipcidr_count = count_lines(output_dir / f"{OUTPUT_PREFIX}_{kind.value}_ipcidr.txt")
        total_domains += domain_count
        total_ipcidrs += ipcidr_count
        rules[kind.value] = rule_stat_payload(domain_count, ipcidr_count)
        add_mrs_file_stats(output_dir, kind, domain_count, ipcidr_count, mrs)

    totals = rule_stat_payload(total_domains, total_ipcidrs)
    return {
        "schema_version": 1,
        "rules": rules,
        "totals": totals,
        "mrs": mrs,
        "badges": {
            "ads_domains": rules[RuleKind.ADS.value]["domains_display"],
            "allow_domains": rules[RuleKind.ALLOW.value]["domains_display"],
            "malware_domains": rules[RuleKind.MALWARE.value]["domains_display"],
            "total_rules": totals["total_display"],
            "ads_mrs_size": mrs[RuleKind.ADS.value]["display"],
        },
    }


def count_lines(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8") as output_file:
        for line in output_file:
            if line.strip():
                count += 1
    return count


def rule_stat_payload(domains: int, ipcidrs: int) -> RuleStatPayload:
    total = domains + ipcidrs
    return {
        "domains": domains,
        "ipcidrs": ipcidrs,
        "total": total,
        "domains_display": format_count(domains),
        "ipcidrs_display": format_count(ipcidrs),
        "total_display": format_count(total),
    }


def add_mrs_file_stats(
    output_dir: Path,
    kind: RuleKind,
    domain_count: int,
    ipcidr_count: int,
    mrs: dict[str, FileStatPayload],
) -> None:
    add_required_mrs_file(output_dir / f"{OUTPUT_PREFIX}_{kind.value}.mrs", kind.value, domain_count, mrs)
    add_required_mrs_file(
        output_dir / f"{OUTPUT_PREFIX}_{kind.value}_ipcidr.mrs",
        f"{kind.value}_ipcidr",
        ipcidr_count,
        mrs,
    )


def add_required_mrs_file(
    path: Path,
    key: str,
    rule_count: int,
    mrs: dict[str, FileStatPayload],
) -> None:
    if rule_count == 0 and not path.exists():
        return
    size = path.stat().st_size
    mrs[key] = {
        "bytes": size,
        "display": format_bytes(size),
    }


def format_count(value: int) -> str:
    if value < ONE_THOUSAND:
        return str(value)
    if value < TEN_THOUSAND:
        return f"{value / ONE_THOUSAND:.1f}k"
    if value < ONE_MILLION:
        return f"{round(value / ONE_THOUSAND):.0f}k"
    if value < TEN_MILLION:
        return f"{value / ONE_MILLION:.1f}M"
    return f"{round(value / ONE_MILLION):.0f}M"


def format_bytes(value: int) -> str:
    if value < ONE_KIB:
        return f"{value} B"
    if value < ONE_MIB:
        return f"{round(value / ONE_KIB):.0f} KiB"
    if value < ONE_GIB:
        return f"{value / ONE_MIB:.1f} MiB"
    return f"{value / ONE_GIB:.1f} GiB"


def write_stats_file(output_dir: Path) -> Path:
    stats_path = output_dir / STATS_FILE
    payload = build_stats_payload(output_dir)
    _ = stats_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return stats_path


def parse_args(argv: Sequence[str]) -> StatsArgs:
    parser = argparse.ArgumentParser(description="Write AdRulesUltra release statistics JSON.")
    _ = parser.add_argument("--output", type=Path, required=True)
    namespace = parser.parse_args(argv)
    parsed: dict[str, object] = vars(namespace)
    output = parsed["output"]
    if not isinstance(output, Path):
        raise TypeError
    return StatsArgs(output=output)


def main() -> int:
    args = parse_args(sys.argv[1:])
    stats_path = write_stats_file(args.output)
    _ = print(stats_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
