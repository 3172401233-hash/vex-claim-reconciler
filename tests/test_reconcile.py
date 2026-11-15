import unittest
from datetime import datetime, timedelta, timezone

from vex_reconciler import Claim, Source, Status, reconcile

PURL = "pkg:pypi/demo"
VULN = "CVE-2026-0001"
DISCLOSED = datetime(2026, 1, 10, tzinfo=timezone.utc)
T0 = DISCLOSED + timedelta(days=1)
NOW = DISCLOSED + timedelta(days=30)

VENDOR_A = Source("vendor-a", trust=10)
VENDOR_B = Source("vendor-b", trust=20)
VENDOR_C = Source("vendor-c", trust=30)


def make(status, source, published=T0, version_range=">=1.0|<2.0", **kw):
    return Claim(
        vulnerability_id=VULN,
        purl=PURL,
        status=status,
        source=source,
        published_at=published,
        version_range=version_range,
        **kw,
    )


def run(claims, version="1.5", as_of=NOW):
    return reconcile(
        claims, purl=PURL, version=version,
        vulnerability_id=VULN, disclosed_at=DISCLOSED, as_of=as_of,
    )


class MultiVendorConflictTest(unittest.TestCase):
    def test_affected_fixed_not_affected_conflict_yields_unknown(self):
        # 同一漏洞被三家分别标为 affected / fixed / not_affected：
        # 最可信来源说 not_affected，但无法证明，安全优先降级为 unknown。
        claims = [
            make(Status.AFFECTED, VENDOR_A, published=T0),
            make(Status.FIXED, VENDOR_B, published=T0 + timedelta(days=1)),
            make(Status.NOT_AFFECTED, VENDOR_C, published=T0 + timedelta(days=2)),
        ]
        verdict = run(claims)
        self.assertEqual(verdict.status, Status.UNKNOWN)
        self.assertEqual(verdict.primary.status, Status.NOT_AFFECTED)

    def test_highest_trust_affected_wins(self):
        claims = [
            make(Status.NOT_AFFECTED, VENDOR_A),
            make(Status.FIXED, VENDOR_B),
            make(Status.AFFECTED, VENDOR_C),
        ]
        self.assertEqual(run(claims).status, Status.AFFECTED)

    def test_uncontested_not_affected_is_accepted(self):
        claims = [make(Status.NOT_AFFECTED, VENDOR_C)]
        self.assertEqual(run(claims).status, Status.NOT_AFFECTED)

    def test_newer_low_trust_not_affected_does_not_override_affected(self):
        # 最新声明是低可信来源的 not_affected，不能直接采信。
        claims = [
            make(Status.AFFECTED, VENDOR_C, published=T0),
            make(Status.NOT_AFFECTED, VENDOR_A, published=T0 + timedelta(days=5)),
        ]
        self.assertEqual(run(claims).status, Status.AFFECTED)


class ExpiryTest(unittest.TestCase):
    def test_expired_exemption_kept_as_evidence_only(self):
        expired = make(
            Status.NOT_AFFECTED, VENDOR_C,
            expires_at=NOW - timedelta(days=1),
            justification="vulnerable_code_not_present",
        )
        claims = [expired, make(Status.AFFECTED, VENDOR_A, published=T0 + timedelta(days=1))]
        verdict = run(claims)
        self.assertEqual(verdict.status, Status.AFFECTED)
        dispositions = {e.claim: e.disposition for e in verdict.evidence}
        self.assertEqual(dispositions[expired], "expired")

    def test_expired_only_claim_falls_back_to_unknown(self):
        claims = [make(Status.NOT_AFFECTED, VENDOR_C, expires_at=NOW - timedelta(hours=1))]
        verdict = run(claims)
        self.assertEqual(verdict.status, Status.UNKNOWN)
        self.assertEqual(verdict.evidence[0].disposition, "expired")

    def test_unexpired_claim_still_applies(self):
        claims = [make(Status.NOT_AFFECTED, VENDOR_C, expires_at=NOW + timedelta(days=1))]
        self.assertEqual(run(claims).status, Status.NOT_AFFECTED)


class VersionBoundaryTest(unittest.TestCase):
    def test_lower_bound_inclusive(self):
        claims = [make(Status.AFFECTED, VENDOR_C, version_range=">=2.0|<3.0")]
        self.assertEqual(run(claims, version="2.0").status, Status.AFFECTED)

    def test_upper_bound_exclusive(self):
        claims = [make(Status.AFFECTED, VENDOR_C, version_range=">=2.0|<3.0")]
        verdict = run(claims, version="3.0")
        self.assertEqual(verdict.status, Status.UNKNOWN)
        self.assertEqual(verdict.evidence[0].disposition, "version_mismatch")

    def test_version_mismatch_kept_as_evidence(self):
        mismatched = make(Status.NOT_AFFECTED, VENDOR_C, version_range=">=9.0")
        claims = [mismatched, make(Status.AFFECTED, VENDOR_A)]
        verdict = run(claims, version="1.5")
        self.assertEqual(verdict.status, Status.AFFECTED)
        dispositions = {e.claim: e.disposition for e in verdict.evidence}
        self.assertEqual(dispositions[mismatched], "version_mismatch")

    def test_numeric_not_lexicographic_compare(self):
        claims = [make(Status.AFFECTED, VENDOR_C, version_range=">=1.9")]
        self.assertEqual(run(claims, version="1.10").status, Status.AFFECTED)


class DuplicateClaimTest(unittest.TestCase):
    def test_duplicate_claims_counted_once(self):
        claim = make(Status.NOT_AFFECTED, VENDOR_C)
        verdict = run([claim, claim, claim])
        self.assertEqual(verdict.status, Status.NOT_AFFECTED)
        applied = [e for e in verdict.evidence if e.disposition == "applied"]
        duplicates = [e for e in verdict.evidence if e.disposition == "duplicate"]
        self.assertEqual(len(applied), 1)
        self.assertEqual(len(duplicates), 2)

    def test_same_status_from_two_vendors_is_not_duplicate(self):
        claims = [make(Status.AFFECTED, VENDOR_A), make(Status.AFFECTED, VENDOR_B)]
        verdict = run(claims)
        self.assertEqual(verdict.status, Status.AFFECTED)
        self.assertEqual(len(verdict.applied_claims()), 2)


class WithdrawalTest(unittest.TestCase):
    def test_late_withdrawal_excludes_claim(self):
        retracted = make(
            Status.NOT_AFFECTED, VENDOR_C,
            published=T0,
            withdrawn_at=NOW - timedelta(days=1),
        )
        claims = [retracted, make(Status.AFFECTED, VENDOR_A)]
        verdict = run(claims)
        self.assertEqual(verdict.status, Status.AFFECTED)
        dispositions = {e.claim: e.disposition for e in verdict.evidence}
        self.assertEqual(dispositions[retracted], "withdrawn")

    def test_claim_applies_before_withdrawal_arrives(self):
        claim = make(
            Status.NOT_AFFECTED, VENDOR_C,
            published=T0,
            withdrawn_at=T0 + timedelta(days=10),
        )
        early = run([claim], as_of=T0 + timedelta(days=5))
        self.assertEqual(early.status, Status.NOT_AFFECTED)
        late = run([claim], as_of=T0 + timedelta(days=15))
        self.assertEqual(late.status, Status.UNKNOWN)


class SameTimestampTest(unittest.TestCase):
    def test_tie_broken_by_safety_first(self):
        # 同来源可信度、同一时间戳：取更保守状态。
        claims = [
            make(Status.NOT_AFFECTED, VENDOR_B, published=T0),
            make(Status.AFFECTED, VENDOR_B, published=T0),
        ]
        self.assertEqual(run(claims).status, Status.AFFECTED)

    def test_tie_between_fixed_and_unknown(self):
        claims = [
            make(Status.FIXED, VENDOR_B, published=T0),
            make(Status.UNKNOWN, VENDOR_B, published=T0),
        ]
        self.assertEqual(run(claims).status, Status.UNKNOWN)


class DisclosureFilterTest(unittest.TestCase):
    def test_claim_predating_disclosure_is_evidence_only(self):
        stale = make(Status.NOT_AFFECTED, VENDOR_C, published=DISCLOSED - timedelta(days=1))
        verdict = run([stale])
        self.assertEqual(verdict.status, Status.UNKNOWN)
        self.assertEqual(verdict.evidence[0].disposition, "predates_disclosure")


if __name__ == "__main__":
    unittest.main()
