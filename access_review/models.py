"""Data models and loaders for identity, HR, and entitlement exports."""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Dict, List, Optional


def _parse_date(value: str) -> Optional[date]:
    value = (value or "").strip()
    if not value:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y"):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    raise ValueError(f"Unrecognized date format: {value!r}")


def _parse_bool(value: str) -> bool:
    return (value or "").strip().lower() in {"true", "yes", "1", "y", "enabled"}


@dataclass
class Employee:
    employee_id: str
    name: str
    email: str
    department: str
    title: str
    status: str  # Active | Terminated | Leave
    termination_date: Optional[date] = None

    @property
    def is_terminated(self) -> bool:
        return self.status.lower() == "terminated"


@dataclass
class Account:
    account_id: str
    username: str
    email: str
    employee_id: str
    source: str  # e.g. ActiveDirectory, EntraID, Okta
    account_type: str  # human | service
    enabled: bool
    mfa_enabled: bool
    last_login: Optional[date]
    owner: str = ""
    entitlements: List[str] = field(default_factory=list)

    @property
    def is_service(self) -> bool:
        return self.account_type.lower() == "service"


@dataclass
class Policy:
    stale_after_days: int
    privileged_entitlements: List[str]
    sod_conflicts: List[List[str]]
    role_baselines: Dict[str, List[str]]
    universal_entitlements: List[str]

    @classmethod
    def load(cls, path: Path) -> "Policy":
        data = json.loads(Path(path).read_text())
        return cls(
            stale_after_days=int(data.get("stale_after_days", 90)),
            privileged_entitlements=data.get("privileged_entitlements", []),
            sod_conflicts=data.get("sod_conflicts", []),
            role_baselines=data.get("role_baselines", {}),
            universal_entitlements=data.get("universal_entitlements", []),
        )


def load_employees(path: Path) -> Dict[str, Employee]:
    employees: Dict[str, Employee] = {}
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            emp = Employee(
                employee_id=row["employee_id"].strip(),
                name=row["name"].strip(),
                email=row["email"].strip().lower(),
                department=row["department"].strip(),
                title=row["title"].strip(),
                status=row["status"].strip(),
                termination_date=_parse_date(row.get("termination_date", "")),
            )
            employees[emp.employee_id] = emp
    return employees


def load_accounts(identities_path: Path, entitlements_path: Path) -> Dict[str, Account]:
    accounts: Dict[str, Account] = {}
    with open(identities_path, newline="") as fh:
        for row in csv.DictReader(fh):
            acct = Account(
                account_id=row["account_id"].strip(),
                username=row["username"].strip(),
                email=row.get("email", "").strip().lower(),
                employee_id=row.get("employee_id", "").strip(),
                source=row.get("source", "").strip(),
                account_type=row.get("account_type", "human").strip() or "human",
                enabled=_parse_bool(row.get("enabled", "")),
                mfa_enabled=_parse_bool(row.get("mfa_enabled", "")),
                last_login=_parse_date(row.get("last_login", "")),
                owner=row.get("owner", "").strip(),
            )
            accounts[acct.account_id] = acct
    with open(entitlements_path, newline="") as fh:
        for row in csv.DictReader(fh):
            acct = accounts.get(row["account_id"].strip())
            if acct is not None:
                acct.entitlements.append(f'{row["application"].strip()}:{row["entitlement"].strip()}')
    return accounts
