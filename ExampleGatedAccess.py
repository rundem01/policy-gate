# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""GatedAccess — a 50-line consumer of PolicyGate.

Shows the integration pattern: submit an action, wait for judgment, gate
an on-chain operation behind is_permitted. The consumer holds no LLM logic.

Real uses: DAO proposal admission, grant application screening, API key
issuance, content queue gating. Swap out the gated operation (register) for
whatever the consumer needs to protect.
"""

from genlayer import *

import typing


@gl.contract_interface
class IPolicyGate:
    class View:
        def is_permitted(self, action_id: u256) -> bool: ...
        def get_action(self, action_id: u256) -> typing.Any: ...

    class Write:
        def submit(self, description: str) -> u256: ...


class GatedAccess(gl.Contract):
    """
    Constructor: (policy_gate: Address)
    """

    policy_gate: Address
    registered: TreeMap[Address, bool]
    # Maps registrant → the action_id their registration was judged under.
    registration_action: TreeMap[Address, u256]

    def __init__(self, policy_gate: Address):
        self.policy_gate = policy_gate

    @gl.public.write
    def request_registration(self, intent_description: str) -> u256:
        """Submit an intent to the PolicyGate and store the action_id.

        The caller must call register() after the judgment lands. Separating
        these steps means the LLM call is paid once and the result is reusable.
        """
        gate = gl.get_contract_at(self.policy_gate)
        action_id = gate.write().submit(intent_description)
        self.registration_action[gl.message.sender_address] = action_id
        return action_id

    @gl.public.write
    def register(self) -> None:
        """Complete registration iff the policy verdict is PERMITTED.

        The caller must have previously called request_registration and the
        PolicyGate must have judged the action. Calling register() while the
        action is still PENDING reverts — the judgment is not yet settled.
        """
        caller = gl.message.sender_address
        action_id = self.registration_action.get(caller, None)
        if action_id is None:
            raise gl.vm.UserError("no pending registration — call request_registration first")
        if self.registered.get(caller, False):
            raise gl.vm.UserError("already registered")

        gate = gl.get_contract_at(self.policy_gate)
        # is_permitted returns False for PENDING, STALE, DENIED, and UNADDRESSED.
        if not gate.view().is_permitted(action_id):
            action = gate.view().get_action(action_id)
            status = int(action.get("status", 0))
            if status == 0:
                raise gl.vm.UserError("judgment not yet settled — try again later")
            raise gl.vm.UserError("registration not permitted under current policy")

        self.registered[caller] = True

    @gl.public.view
    def is_registered(self, who: Address) -> bool:
        return bool(self.registered.get(who, False))
