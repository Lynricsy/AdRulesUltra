from __future__ import annotations

import base64
from pathlib import Path
from typing import Final

# 经 mihomo -t 加载验证的 0 条 ipcidr MRS (zstd 帧 + MRS 头, count=0).
# 不使用占位 CIDR, 避免改变 allow/拦截语义.
EMPTY_IPCIDR_MRS_B64: Final[str] = "KLUv/SQohQAAQE1SUwEBAAEAAgBgxh0oAiJw+dQ="
EMPTY_IPCIDR_MRS_BYTES: Final[bytes] = base64.b64decode(EMPTY_IPCIDR_MRS_B64)
EMPTY_IPCIDR_TEXT_PLACEHOLDER: Final[str] = "# empty ipcidr ruleset\n"


def write_empty_ipcidr_mrs(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_bytes(EMPTY_IPCIDR_MRS_BYTES)


def ipcidr_text_has_rules(text: str) -> bool:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            return True
    return False


def ensure_ipcidr_mrs_from_text(text_path: Path, mrs_path: Path) -> str:
    """根据 text 生成 mrs; 无有效规则时写入空集合 MRS, 返回 used|empty."""
    text = text_path.read_text(encoding="utf-8") if text_path.is_file() else ""
    if ipcidr_text_has_rules(text):
        return "used"
    write_empty_ipcidr_mrs(mrs_path)
    return "empty"
