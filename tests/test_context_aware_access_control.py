"""Direct-mode tests for the ContextAwareAccessControl contract.

Covers: policy creation + owner-only revocation, decision binding (validators
agree on allow/deny for the exact policy + context), requestor_history being
maintained, and lifecycle guards (expiry, use limits, inactive policies).
"""

import json
import re
from datetime import datetime, timedelta

from gltest.direct import create_address

ALLOW_JSON = json.dumps({"decision": "allow", "reasoning": "Context satisfies the required signal.", "confidence": 90})
DENY_JSON = json.dumps({"decision": "deny", "reasoning": "Context lacks the required signal.", "confidence": 90})


def _warp_days(vm, days):
    raw = vm._datetime.replace("Z", "").replace("+00:00", "")
    base = datetime.fromisoformat(raw)
    vm.warp((base + timedelta(days=days)).isoformat())


def _create_policy(contract, vm, owner):
    vm.sender = owner
    return contract.create_policy(
        name="Admin Access",
        description="Full admin access policy.",
        resource="/admin/*",
        action="manage",
        required_context="User must be admin with 2FA enabled.",
        max_uses=100,
        expires_in_days=30,
    )


def test_create_and_revoke_policy(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/context_aware_access_control.py")
    owner = create_address("owner")
    other = create_address("other")
    pid = _create_policy(contract, direct_vm, owner)
    assert contract.get_policy(pid)["status"] == "active"

    direct_vm.sender = other
    with direct_vm.expect_revert("Only owner"):
        contract.revoke_policy(pid)

    direct_vm.sender = owner
    contract.revoke_policy(pid)
    assert contract.get_policy(pid)["status"] == "revoked"


def test_check_access_records_requestor_history(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/context_aware_access_control.py")
    owner = create_address("owner")
    requestor = create_address("requestor")
    pid = _create_policy(contract, direct_vm, owner)

    direct_vm.mock_llm(re.escape("context-aware access control evaluator"), ALLOW_JSON)
    direct_vm.sender = requestor
    result = contract.check_access(pid, "/admin/users", "manage", "I have a valid admin session and 2FA.")
    assert result["decision"] == "allow"

    history = contract.get_requestor_history(requestor.as_hex)
    assert len(history) == 1
    assert history[0]["decision"] == "allow"
    assert history[0]["policy_id"] == pid


def test_check_access_validates_inputs(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/context_aware_access_control.py")
    owner = create_address("owner")
    requestor = create_address("requestor")
    pid = _create_policy(contract, direct_vm, owner)

    direct_vm.sender = requestor
    with direct_vm.expect_revert("Resource, action, and context are required"):
        contract.check_access(pid, "", "manage", "ctx")


def test_expired_policy_is_rejected(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/context_aware_access_control.py")
    owner = create_address("owner")
    requestor = create_address("requestor")
    pid = _create_policy(contract, direct_vm, owner)

    # warp 31 days => past the 30-day expiry
    _warp_days(direct_vm, 31)
    direct_vm.sender = requestor
    with direct_vm.expect_revert("Policy has expired"):
        contract.check_access(pid, "/admin/users", "manage", "admin session")


def test_use_limit_enforced(direct_vm, direct_deploy):
    contract = direct_deploy("contracts/context_aware_access_control.py")
    owner = create_address("owner")
    requestor = create_address("requestor")

    direct_vm.sender = owner
    pid = contract.create_policy(
        name="Limited",
        description="One-shot policy.",
        resource="/r",
        action="read",
        required_context="valid token",
        max_uses=1,
        expires_in_days=30,
    )

    direct_vm.mock_llm(re.escape("context-aware access control evaluator"), ALLOW_JSON)
    direct_vm.sender = requestor
    contract.check_access(pid, "/r", "read", "valid token")
    with direct_vm.expect_revert("use limit reached"):
        contract.check_access(pid, "/r", "read", "valid token")


def test_validator_agrees_on_decision(direct_vm, direct_deploy):
    """Validator must accept the stored allow decision and reject a deny when the
    leader proposed allow (same external data)."""
    contract = direct_deploy("contracts/context_aware_access_control.py")
    owner = create_address("owner")
    requestor = create_address("requestor")
    pid = _create_policy(contract, direct_vm, owner)

    direct_vm.mock_llm(re.escape("context-aware access control evaluator"), ALLOW_JSON)
    direct_vm.sender = requestor
    result = contract.check_access(pid, "/admin/users", "manage", "2FA admin session")
    assert result["decision"] == "allow"
    assert result["decision_id"]

    ok = direct_vm.run_validator(leader_result={"decision": "allow"}, index=-1)
    assert ok is True
    bad = direct_vm.run_validator(leader_result={"decision": "deny"}, index=-1)
    assert bad is False