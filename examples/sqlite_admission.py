"""Demonstrate the optional single-host SQLite admission contract.

This example uses ephemeral signing keys and a local SQLite file. It is for
research and education, not production deployment.
"""

from pathlib import Path
from tempfile import TemporaryDirectory
from time import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.core import issue_root_capability
from chainguard.gateway import ActionRequest, EnforcementGateway, sign_action_request
from chainguard.identity import IdentityRegistry
from chainguard.integrity import sign_capability
from chainguard.storage import (
    SQLiteAdmissionCoordinator,
    SQLiteIdentityRegistry,
    SQLiteReplayGuard,
    SQLiteRevocationRegistry,
)


class ReportTool:
    def execute(self, request: ActionRequest) -> dict[str, str]:
        return {"status": "executed", "resource": request.resource}


def main() -> None:
    with TemporaryDirectory() as directory:
        database = Path(directory) / "chainguard.sqlite3"
        human_key = Ed25519PrivateKey.generate()
        agent_key = Ed25519PrivateKey.generate()

        identities = SQLiteIdentityRegistry(database)
        identities.register("human", human_key.public_key().public_bytes_raw())
        identities.register("agent", agent_key.public_key().public_bytes_raw())

        capability = issue_root_capability(
            "human", "agent", {"read"}, {"quarterly-report"},
            audience="report-tool", workflow_id="demo-workflow",
            expires_at=int(time()) + 300,
        )
        chain = (sign_capability(capability, human_key),)
        gateway = EnforcementGateway(
            identities,
            SQLiteRevocationRegistry(database),
            replay_guard=SQLiteReplayGuard(database),
            admission_coordinator=SQLiteAdmissionCoordinator(database),
        )

        request = ActionRequest(
            str(uuid4()), "agent", "read", "quarterly-report",
            "report-tool", "demo-workflow",
        )
        signed = sign_action_request(request, agent_key)
        print(gateway.execute(chain, signed, ReportTool()))


if __name__ == "__main__":
    main()
