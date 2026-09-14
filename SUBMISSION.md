# Submission: Context-Aware Access Control

## Category
Intelligent Contracts

## Contract Name
Context-Aware Access Control

## Summary
A reusable GenLayer primitive for AI-powered access control. Instead of rigid role-based rules, this contract uses LLM reasoning to evaluate complex access scenarios holistically, considering context that cannot be hardcoded.

## What Makes This Unique
- **Context-based evaluation**: LLM analyzes request context against policy requirements
- **Dynamic natural language policies**: Define access rules in plain English
- **Policy effectiveness analysis**: AI reviews decision patterns and suggests improvements
- **Complete audit trail**: Every decision recorded with reasoning
- **Reusable primitive**: Foundation for any protocol needing nuanced permissions

## How Consensus Is Used
The contract uses `gl.vm.run_nondet_unsafe()` with a custom validator function. Each validator independently evaluates the access request by running the same prompt with the provided context. Consensus is reached when validators agree on the allow/deny decision.

## Technical Details
- Python-based GenLayer Intelligent Contract
- Uses `gl.nondet.exec_prompt()` for LLM evaluation
- Custom validator ensures decision consistency
- TreeMap for scalable policy and decision storage
- Policy expiration and use limits

## Use Case
DAO permissions, DeFi access control, NFT-gated content, multi-party authorization - any scenario where rigid rules fail to capture the nuance of real-world access requirements.

## Live Deployment
- **Address**: `0x18C0c4e1131C2402daAAe36baD9C1089f1C24F3c`
- **Network**: GenLayer studionet (chain `61999`)
- **Explorer**: https://explorer-studio.genlayer.com/address/0x18C0c4e1131C2402daAAe36baD9C1089f1C24F3c

## Source Code
See `contracts/context_aware_access_control.py`
