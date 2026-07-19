"""Smoke tests for emit_vex.py — the propose-only OpenVEX authoring CLI.

Covers the load-bearing guarantees a stranger would want proven:
  * a well-formed proposal round-trips through the validator,
  * the OpenVEX authoring rules (not_affected↔justification, affected↔action) are enforced,
  * the vuln-id / staging-dir containment guards actually reject traversal + canonical paths,
  * write_proposal keeps its output inside the staging dir,
  * cmd_validate accepts an emitted document.

Run from this directory:  python -m pytest test_emit_vex.py -q
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from emit_vex import (
    VexError,
    build_document,
    build_statement,
    cmd_validate,
    write_proposal,
)


def _valid_not_affected() -> dict:
    return build_statement(
        vuln="CVE-2021-44228",
        product="pkg:oci/myapp@sha256:abcd",
        status="not_affected",
        justification="vulnerable_code_not_in_execute_path",
        note="runtime evidence",
    )


def test_valid_not_affected_document_round_trips():
    doc = build_document(_valid_not_affected(), author="test-agent")
    # build_document calls _assert_document_valid internally; assert the shape a
    # downstream consumer relies on.
    assert doc["@context"].endswith("v0.2.0")
    assert doc["statements"][0]["justification"] == "vulnerable_code_not_in_execute_path"
    assert doc["version"] == 1


def test_affected_requires_action_statement():
    with pytest.raises(VexError, match="action_statement"):
        build_statement(vuln="CVE-2024-1234", product="pkg:pypi/foo@1.2.3", status="affected")


def test_not_affected_requires_fixed_justification():
    with pytest.raises(VexError, match="justification"):
        build_statement(vuln="CVE-2024-1234", product="pkg:pypi/foo@1.2.3", status="not_affected")
    with pytest.raises(VexError, match="fixed label"):
        build_statement(
            vuln="CVE-2024-1234",
            product="pkg:pypi/foo@1.2.3",
            status="not_affected",
            justification="because_i_said_so",
        )


@pytest.mark.parametrize("bad", ["../../etc/passwd", "CVE/2021/1", "a b", "", "x" * 200])
def test_vuln_id_guard_rejects_path_and_junk(bad):
    with pytest.raises(VexError):
        build_statement(vuln=bad, product="pkg:pypi/foo@1.2.3", status="affected", action_statement="upgrade")


def test_write_proposal_stays_inside_staging_dir(tmp_path: Path):
    doc = build_document(_valid_not_affected(), author="test-agent")
    out = write_proposal(doc, tmp_path / "vex-staging")
    assert out.exists()
    assert out.resolve().is_relative_to((tmp_path / "vex-staging").resolve())
    # The emitted file is itself a valid OpenVEX document.
    parsed = json.loads(out.read_text())
    assert parsed["statements"][0]["vulnerability"]["name"] == "CVE-2021-44228"


def test_write_proposal_refuses_canonical_marker_dir(tmp_path: Path):
    doc = build_document(_valid_not_affected(), author="test-agent")
    with pytest.raises(VexError, match="canonical/promotion"):
        write_proposal(doc, tmp_path / "published-vex")


def test_cmd_validate_accepts_emitted_document(tmp_path: Path, capsys):
    doc = build_document(_valid_not_affected(), author="test-agent")
    out = write_proposal(doc, tmp_path / "vex-staging")
    assert cmd_validate(out) == 0
    assert "VALID" in capsys.readouterr().out
