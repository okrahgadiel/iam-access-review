"""Access review rules. Each rule inspects accounts and yields Findings."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Callable, Dict, Iterable, List

from .models import Account, Employee, Policy

SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}


@dataclass
class Finding:
    rule: str
    severity: str
    account_id: str
    username: str
    detail: str
    recommendation: str

    def as_dict(self) -> Dict[str, str]:
        return self.__dict__.copy()


@dataclass
class Context:
    accounts: Dict[str, Account]
    employees: Dict[str, Employee]
    policy: Policy
    as_of: date


Rule = Callable[[Context], Iterable[Finding]]


def terminated_but_active(ctx: Context) -> Iterable[Finding]:
    """HR says the person left, but the account is still enabled."""
    for acct in ctx.accounts.values():
        emp = ctx.employees.get(acct.employee_id)
        if acct.enabled and emp and emp.is_terminated:
            when = emp.termination_date.isoformat() if emp.termination_date else "unknown date"
            yield Finding(
                "TERMINATED_USER_ACTIVE", "critical", acct.account_id, acct.username,
                f"{emp.name} was terminated on {when} but {acct.source} account is enabled "
                f"with {len(acct.entitlements)} entitlement(s).",
                "Disable the account immediately and revoke all entitlements; review recent activity.",
            )


def orphaned_accounts(ctx: Context) -> Iterable[Finding]:
    """Rogue/orphaned human accounts with no matching HR record."""
    for acct in ctx.accounts.values():
        if acct.is_service or not acct.enabled:
            continue
        if acct.employee_id not in ctx.employees:
            yield Finding(
                "ORPHANED_ACCOUNT", "high", acct.account_id, acct.username,
                f"Enabled human account in {acct.source} has no matching HR record "
                f"(employee_id={acct.employee_id or 'blank'}).",
                "Validate ownership with the application owner; disable if no business owner is found.",
            )


def stale_accounts(ctx: Context) -> Iterable[Finding]:
    limit = ctx.policy.stale_after_days
    for acct in ctx.accounts.values():
        if not acct.enabled:
            continue
        if acct.last_login is None:
            yield Finding(
                "STALE_ACCOUNT", "medium", acct.account_id, acct.username,
                "Enabled account has never logged in.",
                "Confirm the account is still required; disable if unused.",
            )
            continue
        idle = (ctx.as_of - acct.last_login).days
        if idle > limit:
            yield Finding(
                "STALE_ACCOUNT", "medium", acct.account_id, acct.username,
                f"No login for {idle} days (policy limit {limit}).",
                "Disable the dormant account or recertify with the manager.",
            )


def privileged_without_mfa(ctx: Context) -> Iterable[Finding]:
    privileged = set(ctx.policy.privileged_entitlements)
    for acct in ctx.accounts.values():
        # Service accounts can't do interactive MFA; they are covered by the ownership/PAM rule.
        if not acct.enabled or acct.mfa_enabled or acct.is_service:
            continue
        held = sorted(privileged.intersection(acct.entitlements))
        if held:
            yield Finding(
                "PRIVILEGED_NO_MFA", "high", acct.account_id, acct.username,
                f"Holds privileged access ({', '.join(held)}) without MFA.",
                "Enforce MFA via conditional access and vault the credential in the PAM solution.",
            )


def sod_conflicts(ctx: Context) -> Iterable[Finding]:
    for acct in ctx.accounts.values():
        held = set(acct.entitlements)
        for pair in ctx.policy.sod_conflicts:
            if set(pair).issubset(held):
                yield Finding(
                    "SOD_CONFLICT", "high", acct.account_id, acct.username,
                    f"Separation-of-duties conflict: {pair[0]} + {pair[1]}.",
                    "Remove one entitlement or document a compensating control with an approved exception.",
                )


def privilege_creep(ctx: Context) -> Iterable[Finding]:
    """Entitlements outside the department's role baseline."""
    universal = set(ctx.policy.universal_entitlements)
    for acct in ctx.accounts.values():
        emp = ctx.employees.get(acct.employee_id)
        if acct.is_service or not acct.enabled or emp is None or emp.is_terminated:
            continue
        baseline = ctx.policy.role_baselines.get(emp.department)
        if baseline is None:
            continue
        extra = sorted(set(acct.entitlements) - set(baseline) - universal)
        if extra:
            yield Finding(
                "PRIVILEGE_CREEP", "medium", acct.account_id, acct.username,
                f"{len(extra)} entitlement(s) outside the {emp.department} role baseline: {', '.join(extra)}.",
                "Send to the manager for recertification; remove access that is no longer needed.",
            )


def service_account_without_owner(ctx: Context) -> Iterable[Finding]:
    for acct in ctx.accounts.values():
        if acct.is_service and acct.enabled and not acct.owner:
            yield Finding(
                "SERVICE_ACCOUNT_NO_OWNER", "medium", acct.account_id, acct.username,
                "Service account has no accountable owner.",
                "Assign an owner and onboard the credential to the PAM vault with rotation.",
            )


ALL_RULES: List[Rule] = [
    terminated_but_active,
    orphaned_accounts,
    privileged_without_mfa,
    sod_conflicts,
    stale_accounts,
    privilege_creep,
    service_account_without_owner,
]


def run_rules(ctx: Context, rules: List[Rule] = None) -> List[Finding]:
    findings: List[Finding] = []
    for rule in rules or ALL_RULES:
        findings.extend(rule(ctx))
    order = list(SEVERITY_WEIGHT)
    findings.sort(key=lambda f: (order.index(f.severity), f.rule, f.username))
    return findings


def risk_scores(findings: List[Finding]) -> Dict[str, int]:
    scores: Dict[str, int] = {}
    for f in findings:
        scores[f.username] = scores.get(f.username, 0) + SEVERITY_WEIGHT[f.severity]
    return dict(sorted(scores.items(), key=lambda kv: -kv[1]))
