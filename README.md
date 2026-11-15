# vex-claim-reconciler

Python VEX 漏洞可利用性归并库：处理多源声明、截止时间、组件版本和冲突优先级。

## 问题

同一个漏洞在不同供应商的 VEX 中可能分别被标为 `affected`、`fixed`、`not_affected`。
发布门禁若直接采用最新声明，可能把真实受影响的组件误判为安全。本库按确定性的
安全优先规则归并多源声明，给出单一结论并保留全部证据。

## 用法

```python
from datetime import datetime, timezone
from vex_reconciler import Claim, Source, Status, reconcile

claims = [
    Claim("CVE-2026-0001", "pkg:pypi/demo", Status.AFFECTED,
          Source("vendor-a", trust=10), published_at=t1, version_range=">=1.0|<2.0"),
    Claim("CVE-2026-0001", "pkg:pypi/demo", Status.NOT_AFFECTED,
          Source("vendor-c", trust=30), published_at=t2, version_range=">=1.0|<2.0"),
]
verdict = reconcile(claims, purl="pkg:pypi/demo", version="1.5",
                    vulnerability_id="CVE-2026-0001", disclosed_at=disclosed_at)
verdict.status    # Status.UNKNOWN —— 存在 affected 异议，无法证明 not_affected
verdict.evidence  # 每条声明的处置记录（applied / expired / withdrawn / ...）
```

## 归并流程

1. **筛选**：按漏洞 ID、组件 purl、版本范围（vers 风格，如 `vers:pypi/>=1.0|<2.0`）
   和披露时间过滤。早于漏洞披露时间的声明不可信。
2. **排除但留证**：已过期（`expires_at` 已过，如临时豁免到期）和已撤回
   （`withdrawn_at` 已到，含晚到撤回）的声明保留在 `evidence` 中，不参与结论。
3. **去重**：同一来源对同一对象、同一状态、同一时间的完全重复声明只计一次。
4. **裁决**：按 `(来源可信度, 发布时间, 状态保守度)` 取主声明。

## 安全优先裁决规则

状态保守度排序：`affected > unknown > fixed > not_affected`。

- 主声明为宽松状态（`not_affected` / `fixed`）但存在更严重的有效异议时，
  **无法证明宽松状态，结论降级为 `unknown`**——绝不偏向更宽松状态。
- 可信度与发布时间相同（同一时间戳）时，取更保守的状态。
- 低可信来源的 `not_affected` 不能覆盖高可信来源的 `affected`。
- 没有任何适用声明时结论为 `unknown`，而不是宽松状态。
- 被撤回、过期、版本不匹配的声明只影响证据链，不影响结论。

## 测试

```bash
python -m unittest discover -s tests
```

覆盖：多供应商冲突、过期豁免、组件版本边界（含 `1.10 > 1.9` 数值比较）、
重复声明、晚到撤回、同一时间戳平局、披露时间过滤。
