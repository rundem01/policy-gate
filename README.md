# PolicyGate — reviewer fix

This version directly addresses the three reviewer concerns:

1. **Structured authenticated requests**
   - `submit_request()` captures `gl.message.origin_address`.
   - The request binds operation, downstream target, recipient, amount, metadata hash, requester and policy version/hash.
   - `request_hash()` commits to every one of those fields.

2. **Permission receipt bound to the exact operation**
   - `judge()` stores a permission hash after consensus.
   - `verify_permission()` requires the exact requester, operation, target, recipient, amount and metadata hash.
   - Only the exact downstream target can consume the permission.
   - The consuming contract checks the receipt again immediately before its operation.

3. **Consuming contract**
   - `GatedTreasury.py` demonstrates a real downstream operation: an internal credit transfer.
   - It refuses to execute if the PolicyGate receipt is stale, denied, targeted at another contract, owned by another caller, or mismatched.
   - An action can only be consumed once.

## Important deployment change

The corrected `PolicyGate` constructor is:

```text
PolicyGate(policy_text, owner_address)
```

This is intentional. Current GenLayer documentation exposes `sender_address` for transaction execution, while the contract deployment pattern should receive an owner address explicitly. citeturn0search0turn0search4

When deploying in GenLayer Studio, supply:
1. your policy text
2. the owner wallet address

## Correct end-to-end demo

1. Deploy `PolicyGate.py`.
2. Copy its contract address.
3. Deploy `GatedTreasury.py` with the PolicyGate address.
4. Give the test user some internal credits with `credit()`.
5. Submit a structured PolicyGate request whose `target` is the GatedTreasury address and whose operation is exactly `transfer_credits`.
6. Judge the request.
7. Call `GatedTreasury.execute_transfer(action_id)`.
8. The treasury synchronously reads the receipt, calls `verify_permission()`, and only then changes balances.

GenLayer's current contract-interaction docs support synchronous `view()` calls through `gl.get_contract_at()` / `@gl.contract_interface`, and asynchronous writes through `emit()`. citeturn1search0turn2search0

## Why this is better than the old design

The old model was effectively:

```text
caller text → LLM → verdict
```

The new model is:

```text
authenticated origin
       +
exact operation
       +
exact target
       +
exact recipient
       +
exact amount
       +
metadata commitment
       +
policy version/hash
       ↓
   PolicyGate
       ↓
 permission receipt
       ↓
 consuming contract
       ↓
 exact downstream operation
```

This prevents a permission for one operation from being silently reused for another operation.

## Validation

Run locally where the GenLayer toolchain is installed:

```bash
genvm-lint check PolicyGate.py
genvm-lint check GatedTreasury.py
pytest -q tests
```

The GenLayer documentation describes `genvm-lint check` as the contract linter and recommends linting before direct-mode tests. citeturn0search4

This workspace has been Python-AST checked and the pure tests are designed to run with standard pytest. The actual `genvm-lint` / GenLayer direct runtime must still be run in a GenLayer environment before redeployment; I am not claiming a remote Studio deployment has been performed from this workspace.
