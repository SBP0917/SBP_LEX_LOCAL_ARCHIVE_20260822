from pathlib import Path

from sbp_pvpl.constants import (
    AUDIT_MUTATION_ALLOWED,
    BLOCKCHAIN_PUBLICATION_ALLOWED,
    CLOUD_PUBLICATION_ALLOWED,
    DECISION_AUTHORITY_ALLOWED,
    HASH_CHAIN_MUTATION_ALLOWED,
    NETWORK_PUBLICATION_ALLOWED,
    PUBLICATION_ACTIVE,
    RUNTIME_ATTACHED,
    RUNTIME_AUTHORITY,
    TOKEN_MUTATION_ALLOWED,
)
from sbp_pvpl.status import FORBIDDEN_RUNTIME_DECISIONS, PVPLStatus


def test_pvpl_constants_are_detached() -> None:
    assert RUNTIME_ATTACHED is False
    assert PUBLICATION_ACTIVE is False
    assert NETWORK_PUBLICATION_ALLOWED is False
    assert BLOCKCHAIN_PUBLICATION_ALLOWED is False
    assert CLOUD_PUBLICATION_ALLOWED is False
    assert RUNTIME_AUTHORITY == "NONE"
    assert AUDIT_MUTATION_ALLOWED is False
    assert TOKEN_MUTATION_ALLOWED is False
    assert HASH_CHAIN_MUTATION_ALLOWED is False
    assert DECISION_AUTHORITY_ALLOWED is False


def test_pvpl_statuses_do_not_issue_runtime_decisions() -> None:
    assert {status.value for status in PVPLStatus}.isdisjoint(FORBIDDEN_RUNTIME_DECISIONS)


def test_pvpl_does_not_import_runtime_authority_packages() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in Path("sbp_pvpl").rglob("*.py"))
    prohibited_imports = (
        "from sbp_lex.pipeline",
        "from sbp_lex.governance",
        "from sbp_lex.execution",
        "from sbp_lex.security",
        "from sbp_lex.authority_first",
        "from sbp_lex.audit",
        "from sbp_lex.shared",
    )
    assert [item for item in prohibited_imports if item in source] == []
