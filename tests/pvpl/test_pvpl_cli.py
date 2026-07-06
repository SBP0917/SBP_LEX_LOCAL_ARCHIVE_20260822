import sys

from sbp_pvpl.cli import build_local_proof_summary, main


def test_cli_summary_is_local_and_non_authoritative() -> None:
    summary = build_local_proof_summary(".")

    assert summary["summary"]["runtime_authority"] == "NONE"
    assert summary["summary"]["publication_active"] is False
    assert summary["bundle_validation"]["status"] == "PROOF_OK"


def test_cli_without_work_returns_nonzero(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["sbp_pvpl"])

    assert main() == 2
    assert "usage:" in capsys.readouterr().out
