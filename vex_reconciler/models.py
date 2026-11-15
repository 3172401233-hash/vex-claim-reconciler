"""核心数据模型：声明、来源、状态与裁决结果。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import List, Optional


class Status(IntEnum):
    """VEX 状态。数值越大越保守，安全优先裁决直接比较该数值。"""

    NOT_AFFECTED = 1
    FIXED = 2
    UNKNOWN = 3
    AFFECTED = 4

    @classmethod
    def parse(cls, value: "Status | str") -> "Status":
        if isinstance(value, cls):
            return value
        return cls[value.strip().upper()]


@dataclass(frozen=True)
class Source:
    """声明来源。trust 越大越可信，用于冲突裁决。"""

    name: str
    trust: int = 0


@dataclass(frozen=True)
class Claim:
    """一条 VEX 声明。

    - purl: 组件包 URL，如 ``pkg:pypi/requests``。
    - version_range: vers 风格范围，如 ``vers:pypi/>=2.0|<3.0``，
      也接受 ``>=2.0,<3.0`` 或 ``*``；None 表示匹配所有版本。
    - published_at: 声明发布时间，必须不早于漏洞披露时间才可信。
    - expires_at: 声明过期时间（如临时豁免的截止日），过期后仅作证据。
    - withdrawn_at: 撤回时间（晚到撤回），到达后仅作证据。
    """

    vulnerability_id: str
    purl: str
    status: Status
    source: Source
    published_at: datetime
    version_range: Optional[str] = None
    expires_at: Optional[datetime] = None
    withdrawn_at: Optional[datetime] = None
    justification: Optional[str] = None
    detail: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", Status.parse(self.status))
        for attr in ("published_at", "expires_at", "withdrawn_at"):
            value = getattr(self, attr)
            if value is not None and value.tzinfo is None:
                object.__setattr__(self, attr, value.replace(tzinfo=timezone.utc))

    def dedupe_key(self) -> tuple:
        return (
            self.vulnerability_id,
            self.purl,
            self.version_range,
            self.status,
            self.source.name,
            self.published_at,
        )


@dataclass(frozen=True)
class Evidence:
    """一条声明在归并中的处置记录。被排除的声明保留在此，不影响结论。"""

    claim: Claim
    disposition: str  # applied | duplicate | version_mismatch | predates_disclosure | expired | withdrawn | other_vulnerability | other_component
    note: str = ""


@dataclass
class Verdict:
    """归并结论。status 为最终状态，evidence 保留全部声明的处置证据。"""

    status: Status
    reason: str
    vulnerability_id: str
    purl: str
    version: str
    primary: Optional[Claim] = None
    evidence: List[Evidence] = field(default_factory=list)

    def applied_claims(self) -> List[Claim]:
        return [e.claim for e in self.evidence if e.disposition == "applied"]
