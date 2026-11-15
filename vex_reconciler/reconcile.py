"""安全优先的 VEX 声明归并。

流程：
1. 筛选：漏洞 ID、组件 purl、版本范围、披露时间逐一过滤，
   过期与已撤回声明仅保留为证据，不参与结论。
2. 去重：同一来源对同一对象发布的完全重复声明只计一次。
3. 裁决：按 (来源可信度, 发布时间, 状态保守度) 取主声明；
   主声明为宽松状态（not_affected/fixed）但存在更严重的有效异议时，
   降级为 unknown——无法证明宽松状态就绝不采用它。
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Sequence, Tuple

from .models import Claim, Evidence, Status, Verdict
from .versions import version_in_range

LENIENT_STATUSES = (Status.NOT_AFFECTED, Status.FIXED)


def _rank(claim: Claim) -> Tuple[int, datetime, int]:
    """排序键：可信度优先，其次发布时间，最后安全优先（越保守越优）。"""
    return (claim.source.trust, claim.published_at, int(claim.status))


def _classify(
    claim: Claim,
    vulnerability_id: str,
    purl: str,
    version: str,
    disclosed_at: Optional[datetime],
    as_of: datetime,
) -> Tuple[bool, str, str]:
    """返回 (是否参与裁决, 处置, 说明)。顺序即过滤优先级。"""
    if claim.vulnerability_id != vulnerability_id:
        return False, "other_vulnerability", "漏洞 ID 不匹配"
    if claim.purl != purl:
        return False, "other_component", "组件 purl 不匹配"
    if not version_in_range(version, claim.version_range):
        return False, "version_mismatch", f"版本 {version} 不在范围 {claim.version_range!r} 内"
    if disclosed_at is not None and claim.published_at < disclosed_at:
        return False, "predates_disclosure", "声明早于漏洞披露时间，不可信"
    if claim.withdrawn_at is not None and claim.withdrawn_at <= as_of:
        return False, "withdrawn", "声明已被撤回"
    if claim.expires_at is not None and claim.expires_at <= as_of:
        return False, "expired", "声明已过期"
    return True, "applied", ""


def reconcile(
    claims: Sequence[Claim],
    purl: str,
    version: str,
    vulnerability_id: str,
    disclosed_at: Optional[datetime] = None,
    as_of: Optional[datetime] = None,
) -> Verdict:
    """归并针对 (purl, version, vulnerability_id) 的全部声明。

    disclosed_at 为漏洞披露时间，早于它的声明视为不可信证据。
    as_of 为评估时刻（默认当前 UTC 时间），用于判断过期与撤回。
    """
    as_of = as_of or datetime.now(timezone.utc)
    if as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=timezone.utc)
    if disclosed_at is not None and disclosed_at.tzinfo is None:
        disclosed_at = disclosed_at.replace(tzinfo=timezone.utc)

    evidence: List[Evidence] = []
    applicable: List[Claim] = []
    for claim in claims:
        ok, disposition, note = _classify(
            claim, vulnerability_id, purl, version, disclosed_at, as_of
        )
        if ok:
            applicable.append(claim)
        else:
            evidence.append(Evidence(claim=claim, disposition=disposition, note=note))

    # 去重：完全相同的重复声明只保留一条参与裁决，其余仅作证据。
    seen = set()
    unique: List[Claim] = []
    for claim in applicable:
        key = claim.dedupe_key()
        if key in seen:
            evidence.append(Evidence(claim=claim, disposition="duplicate", note="重复声明"))
            continue
        seen.add(key)
        unique.append(claim)
        evidence.append(Evidence(claim=claim, disposition="applied"))

    verdict = Verdict(
        status=Status.UNKNOWN,
        reason="",
        vulnerability_id=vulnerability_id,
        purl=purl,
        version=version,
        evidence=evidence,
    )

    if not unique:
        verdict.status = Status.UNKNOWN
        verdict.reason = "无适用声明，保持 unknown"
        return verdict

    primary = max(unique, key=_rank)
    verdict.primary = primary

    if primary.status in LENIENT_STATUSES:
        objectors = [c for c in unique if c is not primary and c.status > primary.status]
        if objectors:
            # 无法证明宽松状态：存在更严重的有效异议，安全优先降级。
            worst = max(c.status for c in objectors)
            verdict.status = Status.UNKNOWN
            verdict.reason = (
                f"主声明为 {primary.status.name.lower()}（{primary.source.name}），"
                f"但存在 {worst.name.lower()} 级别的有效异议，"
                "无法证明宽松状态，降级为 unknown"
            )
            return verdict

    verdict.status = primary.status
    verdict.reason = (
        f"采用主声明 {primary.status.name.lower()}（{primary.source.name}，"
        f"trust={primary.source.trust}，{primary.published_at.isoformat()}）"
    )
    return verdict
