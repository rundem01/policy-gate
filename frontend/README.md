# Frontend update notes

The old frontend should be updated to call:

- `submit_request(operation, target, recipient, amount, metadata_hash)`
- `judge(action_id)`
- `get_action(action_id)`
- `get_permission_receipt(action_id)`
- `verify_permission(...)` is consumed by the GatedTreasury, not normally called directly by the UI.

The contract constructor now requires `owner_address`, so redeploy PolicyGate and replace the old contract address in Vercel.

For the demo, use:

operation = `transfer_credits`
target = deployed GatedTreasury address
recipient = intended recipient
amount = requested credit amount
metadata_hash = a stable identifier for the request's supporting metadata
