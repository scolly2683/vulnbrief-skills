# Agent SDK guardrails — enforcing propose-then-promote by privilege

This is the enforcement layer for the SKILL.md core rule. When wiring an agent, pipeline, or CI job
to author VEX, the guardrails below *are* the deliverable — the agent being able to draft a statement
is the easy part; the agent being *unable* to publish one, and every attempt being evidenced, is the
part that satisfies an auditor.

The examples use the Claude Agent SDK's two levers — the `allowed_tools` allowlist and the
`PreToolUse` / `PostToolUse` hooks. The exact API surface shifts between SDK versions, so treat the
code as the shape to implement, not a copy-paste contract; check your SDK's current hook signature.

## The principle

- **Convention** proves *intent*: "the agent was told not to promote."
- **Control** proves *enforcement*: "the agent could not promote, and the attempt is in the log."

For SOX ITGC — and any control framework that cares about segregation of duties — only enforcement
counts. Three mechanisms, layered:

1. **`allowed_tools`** — the agent is never *given* the promote capability. This is the primary
   control (blast-radius restriction).
2. **`PreToolUse` deny hook** — defence in depth: even if a tool is mis-scoped, a write aimed at the
   canonical store is refused and logged before it executes.
3. **`PostToolUse` audit hook** — every staging write is appended to an append-only log. This is the
   ITGC evidence.

## 1. allowed_tools — the promote tool is simply absent

Give the triage agent exactly the tools it needs to *propose*, and nothing that can *publish*.

```python
# The agent can read scanner + runtime evidence and write PROPOSALS to staging.
# It is NOT given promote_vex / write_canonical — those live with a human-run tool.
ALLOWED_TOOLS = [
    "read_scanner_findings",     # pull the finding under triage
    "read_runtime_evidence",     # Wiz/Qualys reachability, workload state
    "read_sbom",                 # resolve PURL/CPE identity
    "emit_vex_to_staging",       # <- wraps scripts/emit_vex.py; writes to staging only
    # "promote_vex",             # <- DELIBERATELY ABSENT. Human-only.
    # "write_canonical_store",   # <- DELIBERATELY ABSENT. Human-only.
]

agent = ClaudeAgent(
    system_prompt=TRIAGE_SYSTEM_PROMPT,
    allowed_tools=ALLOWED_TOOLS,        # restrict tools == restrict blast radius
    hooks={"PreToolUse": pre_tool_use, "PostToolUse": post_tool_use},
)
```

The comment lines are load-bearing documentation: a reviewer can see at a glance that the promote
capability was withheld by design, not overlooked.

## 2. PreToolUse — deny + log any reach for the canonical store

```python
CANONICAL_MARKERS = ("canonical", "promoted", "published", "prod-vex")

def pre_tool_use(tool_name: str, tool_input: dict) -> dict:
    """
    Return {"decision": "deny", "reason": ...} to block a call, else {"decision": "allow"}.
    Defence in depth: even a mis-scoped write tool cannot reach the canonical store.
    """
    target = str(tool_input.get("path", "")).lower()

    # Block any write whose destination looks like the canonical / promotion store.
    is_write = tool_name in {"emit_vex_to_staging", "write_file", "fs_write"}
    if is_write and any(m in target for m in CANONICAL_MARKERS):
        audit_append(
            event="TOOL_BLOCKED",
            tool=tool_name,
            detail=f"attempted canonical write to {target!r}",
            actor=AGENT_IDENTITY,
        )
        return {
            "decision": "deny",
            "reason": (
                "Canonical VEX store is human-promote-only. This agent proposes to staging. "
                "Blocked and logged."
            ),
        }

    # Block any attempt to invoke a promote-style tool that shouldn't be in the allowlist at all.
    if tool_name in {"promote_vex", "write_canonical_store"}:
        audit_append(event="TOOL_BLOCKED", tool=tool_name,
                     detail="promote capability is human-only", actor=AGENT_IDENTITY)
        return {"decision": "deny", "reason": "Promotion is a human action. Blocked and logged."}

    return {"decision": "allow"}
```

The `TOOL_BLOCKED` events are as valuable as the successful proposals: they are the positive evidence
that the segregation-of-duties control actually fires, not just that it was configured.

## 3. PostToolUse — append every write to an immutable audit log

```python
import hashlib, json, os
from datetime import datetime, timezone

AUDIT_LOG = "/var/vex-audit/vex-audit.log"   # append-only; ship to a WORM/immutable sink

def audit_append(**record) -> None:
    record.setdefault("timestamp", datetime.now(timezone.utc).isoformat(timespec="seconds"))
    line = json.dumps(record, sort_keys=True)
    # Chain each entry to the previous hash so tampering is detectable.
    prev = _last_audit_hash()
    record_hash = hashlib.sha256((prev + line).encode()).hexdigest()
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps({**record, "prev": prev, "hash": record_hash}) + "\n")

def post_tool_use(tool_name: str, tool_input: dict, tool_result: dict) -> None:
    """Record every VEX proposal the agent successfully writes to staging."""
    if tool_name == "emit_vex_to_staging" and tool_result.get("ok"):
        audit_append(
            event="VEX_PROPOSED",
            actor=AGENT_IDENTITY,
            vulnerability=tool_input.get("vuln"),
            product=tool_input.get("product"),
            status=tool_input.get("status"),
            justification=tool_input.get("justification"),
            staged_path=tool_result.get("path"),
        )
```

Chaining each entry to the previous hash means the log is append-only *and* tamper-evident: an
auditor can verify the chain, and a deleted or altered record breaks it.

## Mapping to SOX ITGC

- **Segregation of duties.** The agent proposes; a human approves. The control is that the agent
  *cannot self-approve* — the promote capability is withheld (`allowed_tools`) and enforced
  (`PreToolUse`). This is the classic "preparer ≠ approver" split, implemented in the tool layer.
- **Evidence of operating effectiveness.** The audit log shows, per finding, that a proposal was
  drafted, by which identity, and that promotion required a separate human action. `TOOL_BLOCKED`
  entries show the control firing.
- **Completeness.** Because the log captures *every* write attempt (allowed and blocked), there is no
  silent path: an auditor can reconcile staged proposals against promoted statements and see nothing
  reached canonical without a human in the loop.

## The one-line test

> Can the agent, by any tool it holds, cause a scanner to stop alerting on a finding without a human
> action in between? If yes, the guardrail is incomplete.

If the answer is no *and* the attempt would be logged, the propose-then-promote contract is enforced
rather than merely intended.
