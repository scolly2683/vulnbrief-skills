---
name: openvex-propose-then-promote
description: >-
  Author OpenVEX vulnerability-exploitability (VEX) statements safely in a regulated or agentic
  context using a propose-then-promote model: an agent writes proposed not_affected statements to a
  staging store, a human promotes them to canonical, and the agent is never given the promote
  capability. Use whenever generating, drafting, staging, or reviewing OpenVEX/VEX statements;
  suppressing scanner false positives with a not_affected verdict; wiring an agent or pipeline to
  write VEX; choosing among the five fixed OpenVEX justification labels; or configuring allowed_tools
  / PreToolUse / PostToolUse hooks so an automated triage agent cannot auto-publish an exploitability
  verdict and every attempt is audited. Also covers SBOM-vs-VEX artifact separation (EU CRA / BSI
  TR-03183-2) and VEX suppression lifecycle (window-gating, staleness, under_investigation). Reach for
  this even when the user only says "suppress this CVE" or "mark it not affected" — those mean VEX
  authoring and this governance applies.
---

# OpenVEX Propose-Then-Promote

VEX (Vulnerability Exploitability eXchange) is a time-ordered sequence of machine-readable
assertions over `{product + vulnerability + status + timestamp}`. It lets you assert exploitability
so scanners stop alerting on findings you have proven irrelevant. This skill governs how VEX gets
*authored* — specifically, how an agent or automation is allowed to produce `not_affected`
suppressions without becoming an unaudited path to silence real findings.

The whole point: suppressing a finding is a risk-acceptance decision. In a regulated environment it
must be attributable to a human and evidenced. This skill makes the agent a fast, accurate drafter
and keeps the human as the sole approver — enforced structurally, not by good intentions.

## The core rule (non-negotiable)

**Propose-then-promote.** An agent that finds evidence supporting a `not_affected` disposition
writes a *proposed* OpenVEX statement to a **staging** location. A **human promotes** it to the
**canonical** store. The agent never auto-publishes `not_affected`.

`affected`, `fixed`, and `under_investigation` are lower-stakes and may be authored more freely, but
`not_affected` is the one that silences a scanner, so it is the one that is gated.

## Enforce by privilege, not convention

This is the load-bearing idea. Do **not** rely on the agent "choosing" not to promote.

- **Convention** — "we agreed the agent wouldn't promote." Proves *intent*.
- **Control** — "the agent *cannot* promote, and any attempt is refused and logged." Proves
  *enforcement*.

For SOX ITGC (and any audit that cares about segregation of duties), only the second counts. Make
the promote/canonical-write tool **absent** from the agent's `allowed_tools` allowlist. Any attempt
to reach the canonical store is then refused and written to the audit trail (e.g. a `TOOL_BLOCKED`
event). `allowed_tools` is a security primitive, not a guideline.

The concrete allowlist, the deny hook, and the append-only audit pattern are in
`references/agent-sdk-guardrails.md`. Read it whenever the task involves wiring an agent, pipeline,
or CI job to write VEX — the guardrails are the deliverable there, not an afterthought.

## The two-store architecture

```
 agent  ──writes proposed──▶  [ STAGING store ]  ──human reviews & promotes──▶  [ CANONICAL store ]
   │                                                                                    │
   └── every write attempt ─────────────────────────────────▶ [ append-only AUDIT log ] ◀── promotions
```

- **Staging store** — the agent holds a write tool scoped here. Statements land as proposals
  (`status_notes: "proposed — pending human promotion"`).
- **Canonical store** — scanners consume from here. Only a human-run promote tool writes here; the
  agent does not hold it.
- **Audit log** — append-only. Records every staging write *and* every blocked attempt to reach
  canonical. This is your ITGC evidence: it shows the agent proposed and could not self-approve.

## Authoring a valid OpenVEX statement

Use `scripts/emit_vex.py` to produce statements. It validates the rules below, writes **only** to a
staging directory, and has **no** promote capability by design — running it is always a proposal,
never a publish. Emitting by hand is error-prone; prefer the script and read its `--help`.

The rules it enforces (full field-level detail in `references/openvex-authoring-reference.md`):

- **Four statuses:** `not_affected`, `affected`, `fixed`, `under_investigation`.
- **`not_affected` MUST carry one of the five FIXED justification labels** (below) — emit the
  *label*, never a free-text `impact_statement`. Prose impact statements are discouraged in the spec
  because they break downstream automation; a label is machine-matchable, prose is not.
- **`affected` MUST carry an `action_statement`** (what a consumer should do).
- **Product identification carries PURL and CPE simultaneously.** OpenVEX is PURL-native (a PURL is a
  valid IRI, so it can be the `@id`), and the `identifiers` block holds `{purl, cpe23, cpe22}` plus
  `hashes`. This is what lets one statement match a PURL-keyed SBOM scanner (Mend/Xray), a CPE-keyed
  scanner (Qualys), and an NVD CPE record at once.
- **Scope with `subcomponents` when the vulnerable package sits inside a larger image.** Assert "the
  X package inside this image is not_affected" rather than suppressing the whole image — otherwise
  one justification silences findings it never covered.
- **CISA minimums:** every statement needs product + status + vulnerability + timestamp; the
  document's `last_updated` must be ≥ the newest statement's timestamp; bump `version` on any change.

## Choosing the justification (evidence → label)

Match the evidence you actually have to the label. Never pick a stronger label than the evidence
supports — the label is an assertion an auditor can challenge.

| Evidence you have | Justification label |
|---|---|
| The vulnerable component isn't in the artifact at all | `component_not_present` |
| The component is present but the specific vulnerable code isn't (e.g. removed, not compiled in) | `vulnerable_code_not_present` |
| The vulnerable code exists but is never reachable at runtime (dead path, disabled feature) | `vulnerable_code_not_in_execute_path` |
| The vulnerable code runs but an adversary can't control the inputs that trigger it | `vulnerable_code_cannot_be_controlled_by_adversary` |
| A built-in mitigation already neutralises it (compile-time/runtime protection *inside the artifact*) | `inline_mitigations_already_exist` |

Note the boundary on the last one: `inline_mitigations_already_exist` is for mitigations *inside the
artifact*. An external compensating control (a WAF virtual patch, a perimeter rule) is a different
thing — it annotates and relaxes an SLA, it does **not** become a `not_affected` justification and it
does **not** re-rate the finding. Keep those separate. Fuller guidance and the CSAF/CycloneDX
crosswalk are in `references/openvex-authoring-reference.md`.

## Suppression lifecycle

A `not_affected` verdict is a claim about a moment in time. Treat it as perishable:

- **Window-gating.** Tie a justification's validity to the runtime evidence that supports it. If the
  evidence was "workload not running / path not reachable" and the workload comes back, the
  suppression should expire and the finding re-surface; when the evidence returns, it re-suppresses.
- **Staleness (e.g. 180 days).** A stale statement **warns and offers renewal but still suppresses**
  — it becomes *untrusted-pending-revalidation*, not false. Auto-un-suppressing everything on
  staleness floods the queue with findings a human already dispositioned; that is worse, not safer.
- **`under_investigation` is non-suppressing.** It is an acknowledgment that triage is in progress,
  not a disposition. It never silences a scanner.

## Keep VEX out of the SBOM (EU CRA / BSI)

**BSI TR-03183-2** — the technical spec the EU Cyber Resilience Act references — forbids embedding
vulnerability data inside the SBOM itself (§3.1, §8.1.14). So VEX MUST be a **separate artifact**,
distributed *alongside* the SBOM, never inside it. This is the regulatory reason to prefer standalone
OpenVEX over CycloneDX-embedded VEX, and to keep a separate PURL-keyed canonical VEX store.

## Consume every format, author one

Author **OpenVEX**. Consume supplier VEX in CSAF (Red Hat, Siemens, SUSE, Cisco, Microsoft) and
CycloneDX by translating it to the canonical OpenVEX labels on ingest (the `openvex/go-vex` crosswalk
is built for this). CycloneDX uses a more granular vocabulary that collapses many-to-one onto the
five canonical justifications — do the translation at the boundary so everything downstream speaks one
vocabulary. Never emit CycloneDX-embedded VEX yourself (see the CRA/BSI rule above).

## What this skill deliberately does NOT do

- **It does not promote.** Promotion to canonical is a human action through a tool the agent must not
  hold. If asked to "just publish it," stop and explain the propose-then-promote contract instead.
- **It does not re-rate on compensating controls.** External mitigations annotate and can relax an
  SLA track; they do not change a finding's rating and they are not `not_affected` justifications.

## References

- `scripts/emit_vex.py` — emit a validated OpenVEX proposal to staging (no promote capability). Run
  `python scripts/emit_vex.py --help`.
- `references/openvex-authoring-reference.md` — full OpenVEX v0.2.0 data model, the five
  justifications in depth, product identification / PURL↔CPE bridge, CISA minimums, the
  canonical↔CSAF↔CycloneDX crosswalk, the CRA/BSI separation rule, and tooling.
- `references/agent-sdk-guardrails.md` — the enforcement layer: an `allowed_tools` allowlist with the
  promote tool absent, a PreToolUse deny hook that blocks and logs canonical writes, and a PostToolUse
  append-only audit hook. Read this for any agent/pipeline wiring task.
