# OpenVEX authoring reference (v0.2.0)

Full field-level detail behind the SKILL.md workflow. Read the section you need.

- [Data model](#data-model)
- [The four statuses](#the-four-statuses)
- [The five not_affected justifications](#the-five-not_affected-justifications)
- [Product identification and the PURL↔CPE bridge](#product-identification-and-the-purlcpe-bridge)
- [CISA minimum requirements](#cisa-minimum-requirements)
- [Justification crosswalk (OpenVEX ↔ CSAF ↔ CycloneDX)](#justification-crosswalk-openvex--csaf--cyclonedx)
- [CRA / BSI separation rule](#cra--bsi-separation-rule)
- [Signing, distribution, tooling](#signing-distribution-tooling)

## Data model

A VEX document is a set of statements. Each **statement** is an assertion over
`{product(s) + vulnerability + status + timestamp}`.

**Document — required:** `@context`, `@id` (an IRI), `author` (machine-readable; SHOULD be crypto-
bound to a signature), `timestamp`, `version` (increment on *any* change). **Optional:** `role`,
`last_updated`, `tooling`, `statements`.

**Statement — required:** `vulnerability`, `status`, `products` (unless inherited from the
document), `timestamp` (unless inherited). **Optional:** `@id`, `version`, `supplier`,
`status_notes`. **Conditional:** `justification` / `impact_statement` (for `not_affected`),
`action_statement` (for `affected`).

## The four statuses

| Status | Meaning | Carries |
|---|---|---|
| `not_affected` | This product is not affected by this vulnerability | a justification **label** (preferred) |
| `affected` | This product is affected; action is recommended | an `action_statement` |
| `fixed` | This product contains a fix for this vulnerability | — |
| `under_investigation` | Whether this product is affected is not yet known | — (non-suppressing) |

`under_investigation` is an acknowledgment, not a disposition — it must never suppress a scanner
finding.

## The five not_affected justifications

`not_affected` MUST carry either a justification label **or** a free-text `impact_statement`. The
spec discourages `impact_statement` because prose can't be matched by automation — **always emit a
label.** The labels are a fixed, closed set:

1. **`component_not_present`** — the vulnerable component is not in the artifact at all.
2. **`vulnerable_code_not_present`** — the component is present, but the specific vulnerable code is
   not (removed, not compiled in, stripped).
3. **`vulnerable_code_not_in_execute_path`** — the vulnerable code is present but never reached at
   runtime (dead path, disabled feature, unloaded class). This is the label most runtime-evidence
   suppressions use.
4. **`vulnerable_code_cannot_be_controlled_by_adversary`** — the vulnerable code executes, but an
   adversary cannot control the inputs needed to trigger it.
5. **`inline_mitigations_already_exist`** — a mitigation *inside the artifact* (compile-time or
   runtime protection) already neutralises the issue.

Pick the label that matches the evidence you can defend, never a stronger one. `inline_mitigations_
already_exist` is specifically for mitigations *inside* the artifact — an external control (WAF
virtual patch, perimeter rule) is not a justification; it annotates and can relax an SLA track, but
it does not make a finding `not_affected` and does not re-rate it.

## Product identification and the PURL↔CPE bridge

OpenVEX `product` and `subcomponent` share a **Component** type:

- **`@id`** — an IRI. A PURL is a valid IRI, so the `@id` can *be* the PURL.
- **`identifiers`** — `{ purl, cpe23, cpe22 }`. This carries PURL **and** CPE on the same statement.
- **`hashes`** — `{ "sha-256": "...", ... }`.
- **`subcomponents[]`** — assert "the X package *inside* this image is not_affected" without
  suppressing the whole image.

Why both identifiers matter: a CVE's affected-products are usually expressed as CPE (from NVD), SBOM
components are PURL (Mend, Xray), and Qualys keys on CPE. Holding both on one statement makes it
matchable by every scanner in the stack. For a durable cross-namespace anchor, resolve CVE-CPE ↔
SBOM-PURL and stamp the statement with purl + cpe (and, if you use it, a GCVE BCP-10 UUIDv5 as the
registry-layer identity).

## CISA minimum requirements

From *CISA Minimum Requirements for VEX* (2023-04):

- Every statement needs **product + status + vulnerability + timestamp**.
- The document's `last_updated` must be **≥** the newest statement's `last_updated`/timestamp.
- Bump `version` whenever anything changes.

`emit_vex.py` enforces these on both emit and `--validate`.

## Justification crosswalk (OpenVEX ↔ CSAF ↔ CycloneDX)

Author OpenVEX; consume the others by translating **to** these canonical labels on ingest. CycloneDX
is more granular and collapses many-to-one.

| OpenVEX (canonical) | CSAF VEX | CycloneDX VEX (translate from) |
|---|---|---|
| `component_not_present` | `component_not_present` | `false_positive` / requires-dependency-ish |
| `vulnerable_code_not_present` | same | `code_not_present` |
| `vulnerable_code_not_in_execute_path` | same | `code_not_reachable` |
| `vulnerable_code_cannot_be_controlled_by_adversary` | same | `requires_configuration` / `requires_environment` / `protected_at_*` |
| `inline_mitigations_already_exist` | same | `protected_by_mitigating_control` |

CSAF status maps directly: `known_affected` → `affected`, `known_not_affected` → `not_affected`,
`fixed` → `fixed`, `under_investigation` → `under_investigation`. CycloneDX uses a different state
vocabulary (`resolved` / `exploitable` / `in_triage` / `false_positive` / `not_affected`) that must
be normalised on ingest. The `openvex/go-vex` library is the crosswalk engine for this.

## CRA / BSI separation rule

**BSI TR-03183-2** (the technical spec the EU Cyber Resilience Act references) forbids embedding
vulnerability data inside the SBOM itself (§3.1, §8.1.14). Therefore:

- VEX MUST be a **separate artifact**, distributed *alongside* the SBOM, never inside it.
- Prefer standalone **OpenVEX** over CycloneDX-embedded VEX.
- Keep a separate, PURL-keyed canonical VEX store.

This is a regulatory constraint, not a style preference.

## Signing, distribution, tooling

- **Signing:** record OpenVEX in Sigstore and/or embed in in-toto attestations so the author is
  cryptographically bound to the statement.
- **Distribution:** alongside the SBOM, not inside it (CRA/BSI).
- **Tooling:**
  - `openvex/go-vex` — generate / transform / consume; the crosswalk engine.
  - `vexctl` — create / merge / attest.
  - **Trivy** — consumes OpenVEX / CSAF / CycloneDX with PURL-keyed filtering.
  - **Dependency-Track** — CycloneDX-native consumer.

## Source

OpenVEX spec v0.2.0 (`openvex/spec`, `OPENVEX-SPEC.md`); CISA *Minimum Requirements for VEX*
(2023-04) and *Status Justifications*; CISA SBOM FAQ (2024); CycloneDX crosswalk discussion #609;
BSI TR-03183-2 (via the EU CRA); Trivy VEX documentation.
