<div align="center">

# Context-Aware Access Control

**Permissions decided by context, not roles — LLM reasoning behind every `allow` / `deny`, agreed by validators.**

![GenLayer](https://img.shields.io/badge/GenLayer-Intelligent%20Contract-6a4cff)
![Python](https://img.shields.io/badge/Python-3.12-3776AB)
![Status](https://img.shields.io/badge/status-live%20on%20studionet-2ea44f)
![Tests](https://img.shields.io/badge/tests-6%20passed-2ea44f)

[Live Contract](https://explorer-studio.genlayer.com/address/0x3f6f4441d88284564DE4298082510f1d74E5Dec0) ·
[GenLayer Docs](https://docs.genlayer.com)

</div>

---

## Why

Rigid rules like `if role == "admin"` can't express "allow this member to act — but only given this validated context, within this policy life span". This primitive turns access control into an **evaluable policy**: creators define natural-language requirements and every request is judged by LLM + validator consensus, with a full audit trail.

## Live Deployment

| | |
|---|---|
| **Contract** | [ContextAwareAccessControl](https://explorer-studio.genlayer.com/address/0x3f6f4441d88284564DE4298082510f1d74E5Dec0) |
| **Address** | `0x3f6f4441d88284564DE4298082510f1d74E5Dec0` |
| **Network** | GenLayer studionet (chain `61999`) |
| **Status** | ✅ deployed + audited on-chain |

## Highlights

- 🧠 **Context-based decisions** — LLM judges request context against natural-language policy requirements
- ✅ **Decision binding** — validators re-run the exact policy + request and must agree on the stored decision
- 🧾 **Attributable audit trail** — every decision stored under its policy **and** its requestor (`requestor_history`)
- ⏳ **Lifecycle guards** — expiry, use limits, owner-only revocation
- 🔓 **Permissionless resolver** — any address can query (it's an access *oracle*), while only the owner mutates

## How It Works

```
create_policy (owner: resource, action, required context, max uses, expiry)
      │
      ▼
check_access(requestor, resource, action, context)
      │
      ▼
  run_nondet_unsafe ──► validators re-run, must agree on allow/deny
      │
      ├── allow ──── decision dX recorded (policy + requestor)
      └── deny  ──── decision dX recorded (policy + requestor)
      │
      ▼ optional
revoke_policy (owner) / evaluate_policy_effectiveness (view)
```

## Methods

| Role | Method | Guard |
|---|---|---|
| Owner | `create_policy`, `revoke_policy` | owner-only |
| Any | `check_access` | input-validated; use-limit / expiry enforced |
| Any | `get_policy`, `get_all_policies`, `get_decision`, `get_policy_decisions`, `get_requestor_history`, `evaluate_policy_effectiveness` | read-only |

## Security Model

- Decision binding in the validator (same prompt → same decision required)
- `requestor_history` maintained on every check (correct per-account rollup)
- Owner-only revocation; expired policies detected; per-policy use limits enforced before evaluation
- Inputs required and length-capped to prevent shadow/garbage requests

## Deploy

```bash
genlayer deploy --contract contracts/context_aware_access_control.py
```

## Test

```bash
pip install -r requirements.txt
pytest tests/
```