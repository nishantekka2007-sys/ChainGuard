"""Run a minimal, local ChainGuard authorization flow.

This is an educational example with ephemeral keys and in-memory state.
It is not a production deployment.
"""

from time import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.core import delegate, issue_root_capability
from chainguard.gateway import ActionRequest, EnforcementGateway, sign_action_request
from chainguard.identity import IdentityRegistry
from chainguard.integrity import sign_capability
from chainguard.revocation import RevocationRegistry


class DemoReportTool:
    """A stand-in for a protected tool adapter."""

    def execute(self, request: ActionRequest) -> dict[str, str]:
        return {
            "status": "executed",
            "action": request.action,
            "resource": request.resource,
            "actor": request.actor,
        }


def main() -> None:
    human_key = Ed25519PrivateKey.generate()
    analyst_key = Ed25519PrivateKey.generate()

    identities = IdentityRegistry()
    identities.register("human", human_key.public_key().public_bytes_raw())
    identities.register("analyst-agent", analyst_key.public_key().public_bytes_raw())

    root = issue_root_capability(
        human="human",
        first_agent="analyst-agent",
        actions={"read", "summarize"},
        resources={"quarterly-report"},
        audience="report-tool",
        workflow_id="quarterly-review-2026",
        expires_at=int(time()) + 300,
    )

    signed_chain = (sign_capability(root, human_key),)
    gateway = EnforcementGateway(identities, RevocationRegistry())

    request = ActionRequest(
        request_id=str(uuid4()),
        actor="analyst-agent",
        action="read",
        resource="quarterly-report",
        audience="report-tool",
        workflow_id="quarterly-review-2026",
    )

    signed_request = sign_action_request(request, analyst_key)
    result = gateway.execute(signed_chain, signed_request, DemoReportTool())
    print(result)


if __name__ == "__main__":
    main()
