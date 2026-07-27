from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from scripts.ruleset_domain import (
    DomainEntry,
    DomainMatchKind,
    classify_domain,
    to_adguard_rule,
    to_dnsmasq_rule,
    to_domain_regex,
    to_mihomo_item,
    to_plain_domain,
    to_smartdns_rule,
    to_surge2_item,
    to_surge_rule,
)
from scripts.ruleset_mrs import EMPTY_IPCIDR_TEXT_PLACEHOLDER
from scripts.ruleset_types import RuleBuckets, RuleKind

OUTPUT_PREFIX: Final[str] = "adrules_ultra"
SING_BOX_RULESET_VERSION: Final[int] = 2

# 动作型 DNS 阻断格式只能用于 ads/malware, allow 没有对称的标准白名单语法。
DNS_SINKHOLE_KINDS: Final[frozenset[RuleKind]] = frozenset({RuleKind.ADS, RuleKind.MALWARE})


@dataclass(frozen=True, slots=True)
class FormatWriteStats:
    kind: RuleKind
    domains_total: int
    domains_exported_plain: int
    domains_skipped_wildcard: int
    domains_skipped_exact_for_sinkhole: int
    domains_subdomain: int
    ipcidrs: int
    wrote_dns_sinkhole: bool


def write_kind_text_formats(kind: RuleKind, buckets: RuleBuckets, output_dir: Path) -> FormatWriteStats:
    domain_entries = sorted((classify_domain(item) for item in buckets.domains), key=lambda item: item.original)
    ipcidrs = sorted(buckets.ipcidrs)
    allow = kind is RuleKind.ALLOW
    wrote_dns_sinkhole = kind in DNS_SINKHOLE_KINDS

    write_mihomo_text(output_dir, kind, domain_entries, ipcidrs)
    write_clash_yaml(output_dir, kind, domain_entries, ipcidrs)
    write_domains_txt(output_dir, kind, domain_entries)
    write_surge_txt(output_dir, kind, domain_entries, ipcidrs)
    write_surge2_txt(output_dir, kind, domain_entries)
    write_adguard_txt(output_dir, kind, domain_entries, allow=allow)
    write_easylist_txt(output_dir, kind, domain_entries, allow=allow)
    write_singbox_source_json(output_dir, kind, domain_entries, ipcidrs)

    skipped_exact_for_sinkhole = 0
    if wrote_dns_sinkhole:
        skipped_exact_for_sinkhole = sum(
            1 for entry in domain_entries if entry.kind is not DomainMatchKind.SUFFIX
        )
        write_dnsmasq_conf(output_dir, kind, domain_entries)
        write_smartdns_conf(output_dir, kind, domain_entries)

    exported_plain = sum(
        1
        for entry in domain_entries
        if entry.kind in {DomainMatchKind.EXACT, DomainMatchKind.SUFFIX}
    )
    skipped_wildcard = sum(1 for entry in domain_entries if entry.kind is DomainMatchKind.WILDCARD)
    subdomain_count = sum(1 for entry in domain_entries if entry.kind is DomainMatchKind.SUBDOMAIN)
    return FormatWriteStats(
        kind=kind,
        domains_total=len(domain_entries),
        domains_exported_plain=exported_plain,
        domains_skipped_wildcard=skipped_wildcard,
        domains_skipped_exact_for_sinkhole=skipped_exact_for_sinkhole,
        domains_subdomain=subdomain_count,
        ipcidrs=len(ipcidrs),
        wrote_dns_sinkhole=wrote_dns_sinkhole,
    )


def write_mihomo_text(
    output_dir: Path,
    kind: RuleKind,
    domain_entries: Sequence[DomainEntry],
    ipcidrs: Sequence[str],
) -> None:
    write_lines(
        output_dir / f"{OUTPUT_PREFIX}_{kind.value}.txt",
        (to_mihomo_item(entry) for entry in domain_entries),
    )
    ipcidr_path = output_dir / f"{OUTPUT_PREFIX}_{kind.value}_ipcidr.txt"
    if ipcidrs:
        write_lines(ipcidr_path, ipcidrs)
    else:
        # 非 0 字节, 保证 Release 始终可下载; 注释不会被 mihomo 当成规则。
        _ = ipcidr_path.write_text(EMPTY_IPCIDR_TEXT_PLACEHOLDER, encoding="utf-8")


def write_clash_yaml(
    output_dir: Path,
    kind: RuleKind,
    domain_entries: Sequence[DomainEntry],
    ipcidrs: Sequence[str],
) -> None:
    # domain 与 ipcidr 分文件, 各自对应 rule-provider behavior。
    _write_clash_payload_yaml(
        output_dir / f"{OUTPUT_PREFIX}_{kind.value}_clash.yaml",
        kind,
        behavior="domain",
        items=[to_mihomo_item(entry) for entry in domain_entries],
    )
    # 空集合也发布 payload: [] , 避免客户端下载 404。
    _write_clash_payload_yaml(
        output_dir / f"{OUTPUT_PREFIX}_{kind.value}_clash_ipcidr.yaml",
        kind,
        behavior="ipcidr",
        items=list(ipcidrs),
    )

def _write_clash_payload_yaml(
    path: Path,
    kind: RuleKind,
    *,
    behavior: str,
    items: Sequence[str],
) -> None:
    lines = [
        f"# AdRulesUltra {kind.value} Clash/mihomo text rule-provider ({behavior})",
        "payload:",
    ]
    if items:
        lines.extend(f"  - '{item}'" for item in items)
    else:
        lines.append("  []")
    _ = path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_domains_txt(output_dir: Path, kind: RuleKind, domain_entries: Sequence[DomainEntry]) -> None:
    write_lines(
        output_dir / f"{OUTPUT_PREFIX}_{kind.value}_domains.txt",
        (domain for entry in domain_entries if (domain := to_plain_domain(entry)) is not None),
    )


def write_surge_txt(
    output_dir: Path,
    kind: RuleKind,
    domain_entries: Sequence[DomainEntry],
    ipcidrs: Sequence[str],
) -> None:
    rules = [rule for entry in domain_entries if (rule := to_surge_rule(entry)) is not None]
    rules.extend(f"IP-CIDR,{ipcidr}" for ipcidr in ipcidrs)
    write_lines(output_dir / f"{OUTPUT_PREFIX}_{kind.value}_surge.txt", rules)


def write_surge2_txt(output_dir: Path, kind: RuleKind, domain_entries: Sequence[DomainEntry]) -> None:
    write_lines(
        output_dir / f"{OUTPUT_PREFIX}_{kind.value}_surge2.txt",
        (item for entry in domain_entries if (item := to_surge2_item(entry)) is not None),
    )


def write_dnsmasq_conf(output_dir: Path, kind: RuleKind, domain_entries: Sequence[DomainEntry]) -> None:
    write_lines(
        output_dir / f"{OUTPUT_PREFIX}_{kind.value}_dnsmasq.conf",
        (rule for entry in domain_entries if (rule := to_dnsmasq_rule(entry)) is not None),
    )


def write_smartdns_conf(output_dir: Path, kind: RuleKind, domain_entries: Sequence[DomainEntry]) -> None:
    write_lines(
        output_dir / f"{OUTPUT_PREFIX}_{kind.value}_smartdns.conf",
        (rule for entry in domain_entries if (rule := to_smartdns_rule(entry)) is not None),
    )


def write_adguard_txt(
    output_dir: Path,
    kind: RuleKind,
    domain_entries: Sequence[DomainEntry],
    *,
    allow: bool,
) -> None:
    write_lines(
        output_dir / f"{OUTPUT_PREFIX}_{kind.value}_adguard.txt",
        (rule for entry in domain_entries if (rule := to_adguard_rule(entry, allow=allow)) is not None),
    )


def write_easylist_txt(
    output_dir: Path,
    kind: RuleKind,
    domain_entries: Sequence[DomainEntry],
    *,
    allow: bool,
) -> None:
    write_lines(
        output_dir / f"{OUTPUT_PREFIX}_{kind.value}_easylist.txt",
        (rule for entry in domain_entries if (rule := to_adguard_rule(entry, allow=allow)) is not None),
    )


def write_singbox_source_json(
    output_dir: Path,
    kind: RuleKind,
    domain_entries: Sequence[DomainEntry],
    ipcidrs: Sequence[str],
) -> None:
    domain: list[str] = []
    domain_suffix: list[str] = []
    domain_regex: list[str] = []
    for entry in domain_entries:
        if entry.kind is DomainMatchKind.EXACT:
            domain.append(entry.value)
        elif entry.kind is DomainMatchKind.SUFFIX:
            domain_suffix.append(entry.value)
        else:
            # SUBDOMAIN / WILDCARD: 用 regex 保留与 +.suffix 的语义边界。
            domain_regex.append(to_domain_regex(entry))

    rule: dict[str, list[str]] = {}
    if domain:
        rule["domain"] = sorted(set(domain))
    if domain_suffix:
        rule["domain_suffix"] = sorted(set(domain_suffix))
    if domain_regex:
        rule["domain_regex"] = sorted(set(domain_regex))
    if ipcidrs:
        rule["ip_cidr"] = sorted(set(ipcidrs))

    payload = {
        "version": SING_BOX_RULESET_VERSION,
        "rules": [rule] if rule else [],
    }
    _ = (output_dir / f"{OUTPUT_PREFIX}_{kind.value}_singbox.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_lines(path: Path, lines: Iterable[str]) -> None:
    values = sorted(set(lines))
    _ = path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")
