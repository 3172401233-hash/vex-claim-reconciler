"""VEX 漏洞可利用性声明归并库（安全优先）。

按组件 purl、版本范围、漏洞 ID 和披露时间筛选多源声明，
再依据来源可信度、发布时间和过期时间解决冲突。
无法证明 not_affected 时保留 unknown 或 affected，绝不偏向更宽松状态。
"""

from .models import Claim, Evidence, Source, Status, Verdict
from .reconcile import reconcile
from .versions import VersionRange, version_in_range

__all__ = [
    "Claim",
    "Evidence",
    "Source",
    "Status",
    "Verdict",
    "VersionRange",
    "reconcile",
    "version_in_range",
]
