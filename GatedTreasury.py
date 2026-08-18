# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
GatedTreasury — consuming contract example for PolicyGate.

This contract demonstrates the safety property requested in review:
PolicyGate is not merely queried as an informational oracle. The exact
permission receipt is checked immediately before the downstream operation.

The downstream operation here is an internal credit transfer, not a real-world
payment. This keeps the demonstration deterministic and safe while showing
the complete authorization boundary.
"""

from genlayer import *


@gl.contract_interface
class PolicyGateInterface:
    class View:
        def get_permission_receipt(self, action_id: u256) -> dict: ...
        def verify_permission(
            self,
            action_id: u256,
            requester: Address,
            operation: str,
            target: Address,
            recipient: Address,
            amount: u256,
            metadata_hash: str,
        ) -> bool: ...


class GatedTreasury(gl.Contract):
    policy_gate: Address
    credits: TreeMap[Address, u256]
    executed_actions: TreeMap[u256, bool]

    def __init__(self, policy_gate_address: str):
        self.policy_gate = Address(policy_gate_address)

    @gl.public.write
    def credit(self, account: Address, amount: u256) -> None:
        if amount == u256(0):
            raise gl.vm.UserError("amount must be greater than zero")
        current = self.credits.get(account, u256(0))
        self.credits[account] = current + amount

    @gl.public.write
    def execute_transfer(self, action_id: u256) -> None:
        if self.executed_actions.get(action_id, False):
            raise gl.vm.UserError("authorization already consumed")

        gate = PolicyGateInterface(self.policy_gate)
        receipt = gate.view().get_permission_receipt(action_id)

        if int(receipt["status"]) != 1:
            raise gl.vm.UserError("authorization is not finalized")
        if int(receipt["verdict"]) != 0:
            raise gl.vm.UserError("authorization is not permitted")
        if receipt["target"] != gl.message.contract_address:
            raise gl.vm.UserError("authorization targets another contract")
        if receipt["requester"] != gl.message.sender_address:
            raise gl.vm.UserError("authorization belongs to another caller")
        if receipt["operation"] != "transfer_credits":
            raise gl.vm.UserError("wrong authorized operation")

        valid = gate.view().verify_permission(
            action_id,
            receipt["requester"],
            receipt["operation"],
            receipt["target"],
            receipt["recipient"],
            u256(receipt["amount"]),
            receipt["metadata_hash"],
        )
        if not valid:
            raise gl.vm.UserError("permission receipt does not match request")

        sender = gl.message.sender_address
        recipient = receipt["recipient"]
        amount = u256(receipt["amount"])

        balance = self.credits.get(sender, u256(0))
        if balance < amount:
            raise gl.vm.UserError("insufficient credits")

        self.credits[sender] = balance - amount
        self.credits[recipient] = self.credits.get(recipient, u256(0)) + amount
        self.executed_actions[action_id] = True

    @gl.public.view
    def get_credit(self, account: Address) -> u256:
        return self.credits.get(account, u256(0))

    @gl.public.view
    def is_executed(self, action_id: u256) -> bool:
        return self.executed_actions.get(action_id, False)

    @gl.public.view
    def get_config(self) -> dict:
        return {
            "policy_gate": self.policy_gate,
            "contract": gl.message.contract_address,
        }
