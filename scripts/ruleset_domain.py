from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

DOMAIN_SUFFIX_PREFIX: Final[str] = "+."
LEADING_DOT_PREFIX: Final[str] = "."
WILDCARD_CHAR: Final[str] = "*"


class DomainMatchKind(StrEnum):
    EXACT = "exact"
    # +.example.com 匹配 apex 与全部子域。
    SUFFIX = "suffix"
    # .example.com 仅匹配子域, 不匹配 apex。
    SUBDOMAIN = "subdomain"
    WILDCARD = "wildcard"


@dataclass(frozen=True, slots=True)
class DomainEntry:
    kind: DomainMatchKind
    value: str
    original: str


def classify_domain(entry: str) -> DomainEntry:
    raw = entry.strip()
    if not raw:
        message = "empty domain entry"
        raise ValueError(message)

    if raw.startswith(DOMAIN_SUFFIX_PREFIX):
        value = raw[len(DOMAIN_SUFFIX_PREFIX) :].lstrip(".")
        if not value:
            message = f"invalid domain suffix entry: {entry}"
            raise ValueError(message)
        kind = DomainMatchKind.WILDCARD if WILDCARD_CHAR in value else DomainMatchKind.SUFFIX
        return DomainEntry(kind=kind, value=value, original=raw)

    if raw.startswith(LEADING_DOT_PREFIX) and len(raw) > 1:
        value = raw[1:].lstrip(".")
        if not value:
            message = f"invalid leading-dot domain entry: {entry}"
            raise ValueError(message)
        kind = DomainMatchKind.WILDCARD if WILDCARD_CHAR in value else DomainMatchKind.SUBDOMAIN
        return DomainEntry(kind=kind, value=value, original=raw)

    value = raw.strip(".")
    if not value:
        message = f"invalid domain entry: {entry}"
        raise ValueError(message)
    kind = DomainMatchKind.WILDCARD if WILDCARD_CHAR in value else DomainMatchKind.EXACT
    return DomainEntry(kind=kind, value=value, original=raw)


def to_mihomo_item(entry: DomainEntry) -> str:
    # 原样回写, 避免 .example.com 被改写成 +.example.com。
    return entry.original


def to_plain_domain(entry: DomainEntry) -> str | None:
    # domains.txt 只保留 exact/suffix 字面域名; 跳过 subdomain/wildcard, 避免静默扩大。
    if entry.kind in {DomainMatchKind.EXACT, DomainMatchKind.SUFFIX}:
        return entry.value
    return None


def to_surge_rule(entry: DomainEntry) -> str | None:
    if entry.kind is DomainMatchKind.EXACT:
        return f"DOMAIN,{entry.value}"
    if entry.kind is DomainMatchKind.SUFFIX:
        return f"DOMAIN-SUFFIX,{entry.value}"
    if entry.kind is DomainMatchKind.SUBDOMAIN:
        # 仅子域近似匹配; 不能用会命中 apex 的 DOMAIN-SUFFIX。
        return f"DOMAIN-WILDCARD,*.{entry.value}"
    return None


def to_surge2_item(entry: DomainEntry) -> str | None:
    if entry.kind is DomainMatchKind.EXACT:
        return entry.value
    if entry.kind is DomainMatchKind.SUFFIX:
        return f".{entry.value}"
    # DOMAIN-SET 的 .host 通常包含 apex; 纯 subdomain 不导出。
    return None


def to_dnsmasq_rule(entry: DomainEntry) -> str | None:
    # address=/host/ 会匹配 host 与子域; 仅对明确的 suffix 导出。
    if entry.kind is DomainMatchKind.SUFFIX:
        return f"address=/{entry.value}/"
    return None


def to_smartdns_rule(entry: DomainEntry) -> str | None:
    if entry.kind is DomainMatchKind.SUFFIX:
        return f"address /{entry.value}/#"
    return None


def to_adguard_rule(entry: DomainEntry, *, allow: bool) -> str | None:
    if entry.kind is DomainMatchKind.WILDCARD:
        return None
    if entry.kind is DomainMatchKind.EXACT:
        # hosts 风格精确域名; ||domain^ 会扩大到全部子域。
        return f"@@{entry.value}" if allow else entry.value
    if entry.kind is DomainMatchKind.SUBDOMAIN:
        # 仅子域: 用 DNS 正则, 避免命中 apex。
        regex = rf"/^.+\.{_escape_regex_literal(entry.value)}$/"
        return f"@@{regex}" if allow else regex
    prefix = "@@" if allow else ""
    return f"{prefix}||{entry.value}^"


def to_domain_regex(entry: DomainEntry) -> str:
    if entry.kind is DomainMatchKind.EXACT:
        return f"^{_escape_regex_literal(entry.value)}$"
    if entry.kind is DomainMatchKind.SUBDOMAIN:
        return rf"^.+\.{_escape_regex_literal(entry.value)}$"
    if entry.kind is DomainMatchKind.SUFFIX:
        return rf"^(?:.+\.)?{_escape_regex_literal(entry.value)}$"
    escaped = _escape_regex_literal_with_wildcards(entry.value)
    if entry.original.startswith(DOMAIN_SUFFIX_PREFIX) or entry.original.startswith(LEADING_DOT_PREFIX):
        return rf"^(?:.+\.)?{escaped}$"
    return f"^{escaped}$"


def _escape_regex_literal(value: str) -> str:
    parts: list[str] = []
    for char in value:
        if char in {".", "+", "?", "^", "$", "{", "}", "(", ")", "|", "[", "]", "\\", "*"}:
            parts.append(f"\\{char}")
            continue
        parts.append(char)
    return "".join(parts)


def _escape_regex_literal_with_wildcards(value: str) -> str:
    parts: list[str] = []
    for char in value:
        if char == WILDCARD_CHAR:
            parts.append(".*")
            continue
        if char in {".", "+", "?", "^", "$", "{", "}", "(", ")", "|", "[", "]", "\\"}:
            parts.append(f"\\{char}")
            continue
        parts.append(char)
    return "".join(parts)
