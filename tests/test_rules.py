import unittest
from datetime import date
from pathlib import Path

from access_review.models import Account, Employee, Policy, load_accounts, load_employees
from access_review.rules import (
    Context,
    orphaned_accounts,
    privilege_creep,
    privileged_without_mfa,
    risk_scores,
    run_rules,
    service_account_without_owner,
    sod_conflicts,
    stale_accounts,
    terminated_but_active,
)

DATA = Path(__file__).resolve().parent.parent / "sample_data"
AS_OF = date(2026, 11, 11)


def make_policy(**overrides):
    base = dict(
        stale_after_days=90,
        privileged_entitlements=["AD:Domain Admins"],
        sod_conflicts=[["ERP:Create", "ERP:Approve"]],
        role_baselines={"Finance": ["ERP:Create"]},
        universal_entitlements=["M365:User"],
    )
    base.update(overrides)
    return Policy(**base)


def acct(account_id="A1", employee_id="E1", enabled=True, mfa=True, last_login=AS_OF,
         ents=None, account_type="human", owner=""):
    return Account(account_id, f"user{account_id}", "", employee_id, "EntraID", account_type,
                   enabled, mfa, last_login, owner, list(ents or []))


def emp(employee_id="E1", status="Active", dept="Finance"):
    return Employee(employee_id, "Test User", "t@example.com", dept, "Analyst", status)


def ctx(accounts, employees, policy=None):
    return Context({a.account_id: a for a in accounts}, {e.employee_id: e for e in employees},
                   policy or make_policy(), AS_OF)


class RuleTests(unittest.TestCase):
    def test_terminated_user_with_enabled_account_is_critical(self):
        found = list(terminated_but_active(ctx([acct()], [emp(status="Terminated")])))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "critical")

    def test_terminated_user_with_disabled_account_is_clean(self):
        self.assertEqual(list(terminated_but_active(ctx([acct(enabled=False)], [emp(status="Terminated")]))), [])

    def test_orphaned_account_detected_but_service_accounts_skipped(self):
        accounts = [acct("A1", employee_id="NOPE"), acct("A2", employee_id="", account_type="service", owner="x")]
        found = list(orphaned_accounts(ctx(accounts, [emp()])))
        self.assertEqual([f.account_id for f in found], ["A1"])

    def test_stale_account_after_policy_window(self):
        old = acct(last_login=date(2026, 6, 1))
        never = acct("A2", last_login=None)
        fresh = acct("A3", last_login=date(2026, 11, 1))
        found = {f.account_id for f in stale_accounts(ctx([old, never, fresh], [emp()]))}
        self.assertEqual(found, {"A1", "A2"})

    def test_privileged_without_mfa(self):
        risky = acct(mfa=False, ents=["AD:Domain Admins"])
        safe = acct("A2", mfa=True, ents=["AD:Domain Admins"])
        svc = acct("A3", mfa=False, ents=["AD:Domain Admins"], account_type="service", owner="x")
        found = [f.account_id for f in privileged_without_mfa(ctx([risky, safe, svc], [emp()]))]
        self.assertEqual(found, ["A1"])

    def test_sod_conflict(self):
        found = list(sod_conflicts(ctx([acct(ents=["ERP:Create", "ERP:Approve"])], [emp()])))
        self.assertEqual(len(found), 1)

    def test_privilege_creep_ignores_universal_entitlements(self):
        a = acct(ents=["ERP:Create", "M365:User", "WMS:Adjust"])
        found = list(privilege_creep(ctx([a], [emp()])))
        self.assertEqual(len(found), 1)
        self.assertIn("WMS:Adjust", found[0].detail)
        self.assertNotIn("M365:User", found[0].detail)

    def test_service_account_without_owner(self):
        a = acct(account_type="service", owner="")
        self.assertEqual(len(list(service_account_without_owner(ctx([a], [])))), 1)


class SampleDataTests(unittest.TestCase):
    def test_end_to_end_on_sample_data(self):
        employees = load_employees(DATA / "hr_roster.csv")
        accounts = load_accounts(DATA / "identities.csv", DATA / "entitlements.csv")
        findings = run_rules(Context(accounts, employees, Policy.load(DATA / "policy.json"), AS_OF))
        rules = {f.rule for f in findings}
        self.assertTrue({"TERMINATED_USER_ACTIVE", "ORPHANED_ACCOUNT", "SOD_CONFLICT",
                         "PRIVILEGED_NO_MFA", "STALE_ACCOUNT"}.issubset(rules))
        self.assertEqual(findings[0].severity, "critical")  # sorted most severe first
        scores = risk_scores(findings)
        self.assertEqual(next(iter(scores)), "admin_test")


if __name__ == "__main__":
    unittest.main()
