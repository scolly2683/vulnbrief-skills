# vulnbrief-skills

Public [Agent Skills](https://docs.claude.com/en/docs/claude-code/skills) for vulnerability
management and CTEM.

The first skill, **`openvex-propose-then-promote`**, governs how an AI agent authors
[OpenVEX](https://openvex.dev) statements: it proposes `not_affected` suppressions to a *staging*
store, and only a human can promote them to the *canonical* store scanners consume from. The agent is
never given the promote capability — segregation of duties is enforced by privilege (`allowed_tools`,
deny hooks, append-only audit), not by convention.

The one-line test the skill is built around:

> Can the agent, by any tool it holds, cause a scanner to stop alerting without a human action in
> between? If yes, the guardrail is incomplete.

## What's in the skill

| Path | What it is |
|------|------------|
| `openvex-propose-then-promote/SKILL.md` | The skill itself — the propose-then-promote model, the five fixed `not_affected` justifications, the suppression lifecycle, and non-goals. |
| `.../scripts/emit_vex.py` | A dependency-free CLI that emits a **validated** OpenVEX v0.2.0 proposal to a staging dir (and a `--validate` mode). It can only propose — it has no promote path, and it refuses to write to anything that looks like a canonical store or outside its staging dir. |
| `.../scripts/test_emit_vex.py` | Smoke tests for the authoring rules and the containment guards. |
| `.../references/agent-sdk-guardrails.md` | The enforcement layer: `allowed_tools` allowlist (promote deliberately absent), PreToolUse deny hook, PostToolUse append-only audit hook. |
| `.../references/openvex-authoring-reference.md` | Field-level OpenVEX v0.2.0 reference (data model, statuses, justifications, PURL↔CPE, CISA minimums). |

## Usage

```bash
# Propose a not_affected suppression scoped to a package inside an image:
python openvex-propose-then-promote/scripts/emit_vex.py \
    --vuln CVE-2021-44228 \
    --product "pkg:oci/myapp@sha256:abcd..." \
    --subcomponent "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" \
    --status not_affected \
    --justification vulnerable_code_not_in_execute_path \
    --note "JNDI lookup path disabled; class not loaded at runtime" \
    --author "triage-agent" \
    --staging-dir ./vex-staging

# Validate an existing OpenVEX document without writing:
python openvex-propose-then-promote/scripts/emit_vex.py --validate ./vex-staging/vex-CVE-2021-44228-....json
```

## Testing

```bash
cd openvex-propose-then-promote/scripts && python -m pytest test_emit_vex.py -q
```

CI runs these on every push and PR (`.github/workflows/ci.yml`).

## License

[MIT](./LICENSE) © 2026 Donal Scollan. Independent, non-commercial project — not affiliated with,
sponsored by, or endorsed by any company or organization.
