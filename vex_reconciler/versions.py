"""极简版本比较与 vers 风格范围匹配（仅标准库）。

支持 ``vers:<scheme>/<约束>`` 或裸约束串，约束以 ``|`` 或 ``,`` 分隔，
比较符为 ``>=``、``<=``、``>``、``<``、``==``、``!=``；``*`` 或空串匹配全部。
版本按数字/非数字分段比较，``1.10`` 大于 ``1.9``。
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

_TOKEN_RE = re.compile(r"(\d+|[a-zA-Z]+)")
_CONSTRAINT_RE = re.compile(r"^(>=|<=|==|!=|>|<)?\s*(.+)$")


def _tokenize(version: str) -> Tuple[Tuple[int, object], ...]:
    tokens: List[Tuple[int, object]] = []
    for part in _TOKEN_RE.findall(version.strip().lower()):
        if part.isdigit():
            tokens.append((1, int(part)))
        else:
            tokens.append((0, part))
    return tuple(tokens)


def compare_versions(left: str, right: str) -> int:
    a, b = _tokenize(left), _tokenize(right)
    for ta, tb in zip(a, b):
        if ta == tb:
            continue
        # 数字段排在字母段之后（1.0 > 1.0rc1），同类型按值比较。
        if ta[0] != tb[0]:
            return 1 if ta[0] > tb[0] else -1
        return 1 if ta[1] > tb[1] else -1
    if len(a) == len(b):
        return 0
    # 前缀相同则剩余段全为零者视为相等（1.0 == 1.0.0）。
    rest = a[len(b):] if len(a) > len(b) else b[len(a):]
    if all(t == (1, 0) for t in rest):
        return 0
    return 1 if len(a) > len(b) else -1


class VersionRange:
    """解析并匹配 vers 风格版本范围。"""

    def __init__(self, spec: Optional[str]) -> None:
        self.spec = spec
        self.constraints: List[Tuple[str, str]] = []
        if spec is None:
            return
        body = spec.strip()
        if body.lower().startswith("vers:"):
            # vers:pypi/>=1.0|<2.0 -> 去掉 scheme 前缀
            body = body.split("/", 1)[1] if "/" in body else ""
        for item in re.split(r"[|,]", body):
            item = item.strip()
            if not item or item == "*":
                continue
            match = _CONSTRAINT_RE.match(item)
            if not match:
                raise ValueError(f"invalid version constraint: {item!r}")
            op = match.group(1) or "=="
            self.constraints.append((op, match.group(2).strip()))

    def matches(self, version: str) -> bool:
        for op, bound in self.constraints:
            cmp = compare_versions(version, bound)
            if op == ">=" and cmp < 0:
                return False
            if op == "<=" and cmp > 0:
                return False
            if op == ">" and cmp <= 0:
                return False
            if op == "<" and cmp >= 0:
                return False
            if op == "==" and cmp != 0:
                return False
            if op == "!=" and cmp == 0:
                return False
        return True


def version_in_range(version: str, spec: Optional[str]) -> bool:
    return VersionRange(spec).matches(version)
