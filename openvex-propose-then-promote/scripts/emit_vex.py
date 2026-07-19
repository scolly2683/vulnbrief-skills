#!/usr/bin/env python3
"""
emit_vex.py — Emit a *validated* OpenVEX v0.2.0 statement as a PROPOSAL to a staging store.

This tool can only propose. It writes to a staging directory and has no capability to promote a
statement to a canonical store — that is a human action, performed by a separate tool the agent must
not hold in its allowed_tools allowlist (see references/agent-sdk-guardrails.md).

Design rules enforced here:
  - not_affected  MUST carry one of the five fixed justification labels (never a prose impact_statement).
  - affected      MUST carry an action_statement.
  - CISA minimums: product + status + vulnerability + timestamp on every statement;
                   document last_updated >= newest statement timestamp; version present.
  - under_investigation is emitted as-is (it is non-suppressing downstream; this tool does not suppress).
  - Refuses to write anywhere that looks like a canonical/promotion path.

Usage examples
--------------
  # Propose a not_affected suppression scoped to a package inside an image:
  python emit_vex.py \
      --vuln CVE-2021-44228 \
      --product "pkg:oci/myapp@sha256:abcd..." \
      --subcomponent "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" \
      --status not_affected \
      --justification vulnerable_code_not_in_execute_path \
      --note "JNDI lookup path disabled; class not loaded at runtime (Wiz runtime evidence 2026-07-04)" \
      --author "vulnbrief-triage-agent" \
      --staging-dir ./vex-staging

  # Propose an affected statement with a required action_statement:
  python emit_vex.py --vuln CVE-2024-1234 --product "pkg:pypi/foo@1.2.3" \
      --status affected --action "Upgrade foo to >= 1.2.5" \
      --author "vulnbrief-triage-agent" --staging-dir ./vex-staging

  # Validate an existing OpenVEX document without writing:
  python emit_vex.py --validate ./vex-staging/vex-CVE-2021-44228-....json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

# Vulnerability ids (CVE-..., GHSA-xxxx-..., GCVE-0-..., ANT-...) are plain
# tokens. Anything outside this set — path separators above all — would flow
# into the proposal filename and could escape the staging dir.
VULN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

VALID_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}

# The five FIXED not_affected justification labels (OpenVEX spec v0.2.0). Emit these, not prose.
FIXED_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}

# Lightweight guard: refuse staging dirs that look like the canonical / promotion store.
CANONICAL_MARKERS = ("canonical", "promoted", "published", "prod-vex")


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_rfc3339(value: str, label: str) -> datetime:
    """Parse an RFC3339 timestamp for comparison.

    String comparison misorders timestamps with mixed UTC offsets, so
    ordering checks must compare parsed datetimes. Naive timestamps are
    treated as UTC rather than rejected (CISA minimums require a timestamp,
    not an offset).
    """
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as e:
        raise VexError(f"{label} is not a valid RFC3339 timestamp: {value!r}") from e
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _short_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


class VexError(ValueError):
    """Raised when a statement/document violates an authoring rule."""


def build_statement(
    vuln: str,
    product: str,
    status: str,
    *,
    justification: str | None = None,
    action_statement: str | None = None,
    subcomponents: list[str] | None = None,
    cpe23: str | None = None,
    sha256: str | None = None,
    note: str | None = None,
    timestamp: str | None = None,
    proposed: bool = True,
) -> dict:
    """Build and validate a single OpenVEX statement dict."""
    if not VULN_ID_RE.fullmatch(vuln or ""):
        raise VexError(
            f"vulnerability id {vuln!r} is not a plain identifier "
            "(letters/digits/._:- only, no path separators)."
        )
    if status not in VALID_STATUSES:
        raise VexError(
            f"status {status!r} is not one of {sorted(VALID_STATUSES)}."
        )

    if status == "not_affected":
        if not justification:
            raise VexError(
                "not_affected requires a justification label. Choose one of: "
                + ", ".join(sorted(FIXED_JUSTIFICATIONS))
                + ". Do NOT substitute a prose impact_statement — it breaks downstream automation."
            )
        if justification not in FIXED_JUSTIFICATIONS:
            raise VexError(
                f"justification {justification!r} is not a valid fixed label. Valid labels: "
                + ", ".join(sorted(FIXED_JUSTIFICATIONS))
            )
    elif justification:
        raise VexError(
            f"justification is only valid for status not_affected, not {status!r}."
        )

    if status == "affected" and not action_statement:
        raise VexError(
            "affected requires an action_statement (what a consumer should do about it)."
        )
    if action_statement and status != "affected":
        raise VexError(
            f"action_statement is only valid for status affected, not {status!r}."
        )

    # Product component. A PURL is a valid IRI, so it doubles as @id.
    identifiers: dict = {"purl": product}
    if cpe23:
        identifiers["cpe23"] = cpe23
    component: dict = {"@id": product, "identifiers": identifiers}
    if sha256:
        component["hashes"] = {"sha-256": sha256}
    if subcomponents:
        component["subcomponents"] = [{"@id": s, "identifiers": {"purl": s}} for s in subcomponents]

    stmt: dict = {
        "vulnerability": {"name": vuln},
        "products": [component],
        "status": status,
        "timestamp": timestamp or _now_rfc3339(),
    }
    if justification:
        stmt["justification"] = justification
    if action_statement:
        stmt["action_statement"] = action_statement

    status_notes = []
    if proposed:
        status_notes.append("proposed — pending human promotion")
    if note:
        status_notes.append(note)
    if status_notes:
        stmt["status_notes"] = " | ".join(status_notes)

    return stmt


def build_document(statement: dict, author: str) -> dict:
    """Wrap a statement in a valid OpenVEX document with CISA-minimum fields."""
    ts = _now_rfc3339()
    doc_id = f"https://openvex.dev/docs/{uuid.uuid4()}"
    doc = {
        "@context": OPENVEX_CONTEXT,
        "@id": doc_id,
        "author": author,
        "role": "Vulnerability Assessment",
        "timestamp": ts,
        "last_updated": ts,  # must be >= newest statement timestamp
        "version": 1,
        "tooling": "emit_vex.py (propose-then-promote)",
        "statements": [statement],
    }
    _assert_document_valid(doc)
    return doc


def _assert_document_valid(doc: dict) -> None:
    """Re-check CISA minimums on a full document (used on emit and on --validate)."""
    for field in ("@context", "@id", "author", "timestamp", "version", "statements"):
        if field not in doc:
            raise VexError(f"document missing required field: {field}")
    if not doc["statements"]:
        raise VexError("document has no statements.")

    newest = None
    for i, stmt in enumerate(doc["statements"]):
        for field in ("vulnerability", "products", "status", "timestamp"):
            if field not in stmt:
                raise VexError(f"statement[{i}] missing required field: {field}")
        if stmt["status"] not in VALID_STATUSES:
            raise VexError(f"statement[{i}] has invalid status {stmt['status']!r}.")
        if stmt["status"] == "not_affected":
            j = stmt.get("justification")
            if not j:
                raise VexError(
                    f"statement[{i}] is not_affected but has no justification label."
                )
            if j not in FIXED_JUSTIFICATIONS:
                raise VexError(f"statement[{i}] has non-fixed justification {j!r}.")
        if stmt["status"] == "affected" and not stmt.get("action_statement"):
            raise VexError(f"statement[{i}] is affected but has no action_statement.")
        ts = _parse_rfc3339(stmt["timestamp"], f"statement[{i}].timestamp")
        newest = ts if newest is None or ts > newest else newest

    last_updated = _parse_rfc3339(
        doc.get("last_updated", doc["timestamp"]), "document last_updated"
    )
    if newest is not None and last_updated < newest:
        raise VexError(
            "document last_updated is older than the newest statement timestamp "
            f"({last_updated.isoformat()} < {newest.isoformat()})."
        )


def _guard_staging_dir(staging_dir: Path) -> None:
    resolved = str(staging_dir.resolve()).lower()
    for marker in CANONICAL_MARKERS:
        if marker in resolved:
            raise VexError(
                f"refusing to write: staging dir {staging_dir} looks like a canonical/promotion "
                f"store (matched {marker!r}). This tool only proposes to a staging store. "
                "Promotion to canonical is a separate, human-run action."
            )


def write_proposal(doc: dict, staging_dir: Path) -> Path:
    _guard_staging_dir(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)
    stmt = doc["statements"][0]
    vuln = stmt["vulnerability"]["name"]
    if not VULN_ID_RE.fullmatch(vuln or ""):
        raise VexError(
            f"vulnerability id {vuln!r} is not a plain identifier — refusing to "
            "use it in a filename."
        )
    product = stmt["products"][0]["@id"]
    fname = f"vex-{vuln}-{_short_hash(product)}-proposed.json"
    out = staging_dir / fname
    # Belt-and-braces containment: the resolved output path must stay inside
    # the staging dir. Write containment is this tool's entire purpose.
    if not out.resolve().is_relative_to(staging_dir.resolve()):
        raise VexError(
            f"refusing to write outside the staging dir: {out}"
        )
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return out


def cmd_validate(path: Path) -> int:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"❌ could not read/parse {path}: {e}")
        return 2
    try:
        _assert_document_valid(doc)
    except VexError as e:
        print(f"❌ INVALID: {e}")
        return 1
    print(f"✅ VALID OpenVEX document: {path} ({len(doc['statements'])} statement(s)).")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Emit a validated OpenVEX proposal to a staging store (propose-only; no promote)."
    )
    p.add_argument("--validate", metavar="FILE", help="Validate an existing OpenVEX doc and exit.")
    p.add_argument("--vuln", help="Vulnerability id (e.g. CVE-2021-44228, GHSA-xxxx).")
    p.add_argument("--product", help="Primary product PURL (used as @id).")
    p.add_argument("--subcomponent", action="append", default=[],
                   help="PURL of a vulnerable sub-package inside the product (repeatable). "
                        "Scopes the assertion so you don't suppress the whole image.")
    p.add_argument("--status", choices=sorted(VALID_STATUSES), help="OpenVEX status.")
    p.add_argument("--justification", choices=sorted(FIXED_JUSTIFICATIONS),
                   help="Required for not_affected. One of the five fixed labels.")
    p.add_argument("--action", help="action_statement — required for affected.")
    p.add_argument("--cpe23", help="Optional CPE 2.3 string (carried alongside the PURL).")
    p.add_argument("--sha256", help="Optional SHA-256 of the artifact.")
    p.add_argument("--note", help="Free-text status note (does NOT replace a justification label).")
    p.add_argument("--author", help="Machine-readable author identity.")
    p.add_argument("--staging-dir", default="./vex-staging",
                   help="Staging directory to write the proposal into (default ./vex-staging).")

    args = p.parse_args(argv)

    if args.validate:
        return cmd_validate(Path(args.validate))

    missing = [f for f in ("vuln", "product", "status", "author") if not getattr(args, f)]
    if missing:
        p.error("missing required argument(s): " + ", ".join("--" + m for m in missing))

    try:
        stmt = build_statement(
            vuln=args.vuln,
            product=args.product,
            status=args.status,
            justification=args.justification,
            action_statement=args.action,
            subcomponents=args.subcomponent,
            cpe23=args.cpe23,
            sha256=args.sha256,
            note=args.note,
        )
        doc = build_document(stmt, author=args.author)
        out = write_proposal(doc, Path(args.staging_dir))
    except VexError as e:
        print(f"❌ {e}")
        return 1

    print(f"✅ PROPOSAL written to staging: {out}")
    print("   This is a proposal, NOT a publish. A human must promote it to the canonical store")
    print("   via a separate tool the agent does not hold. Nothing is suppressed until then.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
