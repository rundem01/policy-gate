"""
API contract tests/checklist for the reviewer-facing structured workflow.

These tests are intentionally lightweight and do not guess a GenLayer test
runner API. The authoritative runtime checks are the GenLayer linter plus the
existing direct-mode test harness from the project.
"""
from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]


def test_contract_files_exist():
    assert (ROOT / "PolicyGate.py").exists()
    assert (ROOT / "GatedTreasury.py").exists()


def test_contracts_parse_as_python():
    ast.parse((ROOT / "PolicyGate.py").read_text())
    ast.parse((ROOT / "GatedTreasury.py").read_text())


def test_policygate_exposes_structured_api():
    source = (ROOT / "PolicyGate.py").read_text()
    for name in [
        "submit_request",
        "judge",
        "verify_permission",
        "get_permission_receipt",
        "get_action",
        "get_policy",
        "get_config",
        "is_permitted",
    ]:
        assert f"def {name}(" in source


def test_consuming_contract_checks_policygate():
    source = (ROOT / "GatedTreasury.py").read_text()
    assert "verify_permission" in source
    assert "execute_transfer" in source
    assert "authorization already consumed" in source
