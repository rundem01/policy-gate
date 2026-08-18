from pathlib import Path
import hashlib
import json
import types

import pytest

CONTRACT = Path(__file__).resolve().parents[1] / "PolicyGate.py"
START = "# ---------------------------------------------------------------------------\n# Pure consensus primitives"
END = "@allow_storage\n@dataclass"


@pytest.fixture(scope="module")
def prims():
    source = CONTRACT.read_text(encoding="utf-8")
    block = source[source.index(START):source.index(END)]
    gl_mod = types.SimpleNamespace(
        nondet=types.SimpleNamespace(exec_prompt=None),
        vm=types.SimpleNamespace(UserError=Exception),
    )
    ns = {
        "json": json,
        "hashlib": hashlib,
        "gl": gl_mod,
        "typing": __import__("typing"),
        "Address": str,
        "u256": int,
        "u32": int,
        "MAX_RULES": 64,
        "MAX_RULE_LEN": 400,
        "MAX_CITE": 8,
        "VERDICT_PERMITTED": 0,
        "VERDICT_DENIED": 1,
        "VERDICT_UNADDRESSED": 2,
    }
    exec(block, ns)
    return ns


def test_policy_limits(prims):
    with pytest.raises(ValueError, match="rule too long"):
        prims["split_rules"]("x" * 401)
    with pytest.raises(ValueError, match="64 rules"):
        prims["split_rules"]("\n".join(f"Rule {i}" for i in range(65)))


def test_policy_hash_stable(prims):
    assert prims["policy_hash"]("hello") == prims["policy_hash"]("hello")
    assert len(prims["policy_hash"]("hello")) == 16


def test_request_hash_binds_every_structured_field(prims):
    h = prims["request_hash"]("0x1", "transfer_credits", "0x2", "0x3", 10, "abc")
    assert h != prims["request_hash"]("0x1", "transfer_credits", "0x2", "0x3", 11, "abc")
    assert h != prims["request_hash"]("0x1", "transfer_credits", "0x2", "0x4", 10, "abc")
    assert h != prims["request_hash"]("0x1", "other", "0x2", "0x3", 10, "abc")


def test_prompt_contains_structured_fields_and_fences(prims):
    prompt = prims["build_policy_prompt"](
        "0x1", "transfer_credits", "0x2", "0x3", 10, "abc", [(1, "Transfers allowed")]
    )
    assert "<requester>0x1</requester>" in prompt
    assert "<operation>transfer_credits</operation>" in prompt
    assert "<target>0x2</target>" in prompt
    assert "<recipient>0x3</recipient>" in prompt
    assert "<amount>10</amount>" in prompt
    assert "<metadata_hash>abc</metadata_hash>" in prompt


@pytest.mark.parametrize(
    "raw, expected",
    [
        ('{"verdict":"permitted","cited_rules":[1],"confidence":90}', {"verdict": 0, "cited_rules": [1], "confidence": 90}),
        ('{"verdict":"denied","cited_rules":[2],"confidence":80}', {"verdict": 1, "cited_rules": [2], "confidence": 80}),
        ('{"verdict":"unaddressed","cited_rules":[],"confidence":0}', {"verdict": 2, "cited_rules": [], "confidence": 0}),
        ("not json", {"verdict": 2, "cited_rules": [], "confidence": 0}),
    ],
)
def test_parse_verdict(prims, raw, expected):
    assert prims["parse_verdict"](raw, 3) == expected


def test_low_confidence_abstains(prims):
    raw = '{"verdict":"permitted","cited_rules":[1],"confidence":39}'
    assert prims["parse_verdict"](raw, 3)["verdict"] == 2


def test_no_citations_abstains(prims):
    raw = '{"verdict":"denied","cited_rules":[],"confidence":95}'
    assert prims["parse_verdict"](raw, 3)["verdict"] == 2


def test_validator_equivalence(prims):
    a = {"verdict": 1, "cited_rules": [2], "confidence": 85}
    b = {"verdict": 1, "cited_rules": [2, 3], "confidence": 75}
    assert prims["verdicts_agree"](a, b)
    assert not prims["verdicts_agree"](
        a, {"verdict": 0, "cited_rules": [2], "confidence": 85}
    )
    assert not prims["verdicts_agree"](
        a, {"verdict": 1, "cited_rules": [3], "confidence": 85}
    )
