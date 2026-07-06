from pathlib import Path

from sbp_oda.constants import (
    AUDIT_MUTATION_ALLOWED,
    CANONICAL_REWRITE_ALLOWED,
    EXECUTION_AUTHORITY_ALLOWED,
    HASH_CHAIN_MUTATION_ALLOWED,
    RUNTIME_AUTHORITY,
    RUNTIME_PIPELINE_MUTATION_ALLOWED,
    TOKEN_MUTATION_ALLOWED,
)
from sbp_oda.status import FORBIDDEN_RUNTIME_AUTHORITY_OUTPUTS, ODAStatus


def test_oda_statuses_do_not_use_runtime_authority_outputs() -> None:
    oda_status_values = {status.value for status in ODAStatus}
    assert oda_status_values.isdisjoint(FORBIDDEN_RUNTIME_AUTHORITY_OUTPUTS)


def test_oda_runtime_authority_constants_are_locked_off() -> None:
    assert RUNTIME_AUTHORITY == "NONE"
    assert CANONICAL_REWRITE_ALLOWED is False
    assert RUNTIME_PIPELINE_MUTATION_ALLOWED is False
    assert EXECUTION_AUTHORITY_ALLOWED is False
    assert AUDIT_MUTATION_ALLOWED is False
    assert TOKEN_MUTATION_ALLOWED is False
    assert HASH_CHAIN_MUTATION_ALLOWED is False


def test_oda_does_not_import_runtime_authority_packages() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in Path("sbp_oda").rglob("*.py"))
    prohibited_imports = (
        "from sbp_lex.governance",
        "from sbp_lex.execution",
        "from sbp_lex.security",
        "from sbp_lex.pipeline",
        "from sbp_lex.authority_first",
        "from sbp_lex.audit",
        "from sbp_lex.shared",
    )
    assert [item for item in prohibited_imports if item in source] == []
