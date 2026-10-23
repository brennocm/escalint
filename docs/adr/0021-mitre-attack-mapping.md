# 0021 — MITRE ATT&CK mapping

Status: Proposed (Phase 1E checkpoint)

## Context

Findings speak IAM ("iam:PassRole + lambda:CreateFunction"); SOC teams, SIEM
content and threat intelligence speak MITRE ATT&CK. Tagging rules with ATT&CK
techniques lets a finding be triaged, reported and correlated in that language.

## Decision

- **Source:** the official STIX 2.1 data in `mitre-attack/attack-stix-data`,
  bundle `enterprise-attack-20.0.json` (Enterprise ATT&CK **v20.0**), pinned by
  version and SHA-256 in `tools/gen-attack`.
- **Extraction:** `tools/gen-attack` (run by `go generate`, never during a scan)
  keeps only the techniques referenced by registered rules — ID, name, tactics,
  version, `revoked`, `deprecated`, platforms — and writes
  `internal/attack/data/attack.json` with the ATT&CK version. The binary embeds
  that file; nothing is downloaded at runtime.
- **Granularity: per rule.** A technique groups many escalation paths, so it is
  a rule label; edges, paths and findings inherit it. Paths carry the
  deduplicated union of their rules' techniques.
- **Rules reference IDs only.** Names and tactics come from the embedded
  extract, so they cannot drift from the pinned version or be mistyped.
- **Validity rule (tested):** every referenced ID exists in the extract, is not
  revoked or deprecated, and lists the `IaaS` platform.
- **No forced mappings:** a rule may have zero techniques if it sets
  `AttackUnmappedReason` (tested). Today only `EL-PARSE-001` uses it.
- **Attribution:** the MITRE copyright notice and license are reproduced in
  `NOTICE`, `THIRD_PARTY_NOTICES.md` and the README, and ATT&CK is referred to
  as a registered trademark of The MITRE Corporation.
- **Upgrades:** bumping the version is a reviewed PR that re-runs
  `gen-attack`; the validity test catches revoked or renamed techniques.

## Alternatives considered

- *Embed the whole bundle (55 MB):* bloats the binary for ~7 techniques.
- *Map per edge:* the same technique would repeat on every step; ATT&CK
  describes behavior, not individual API calls.
- *Hand-written names/tactics:* drift silently (v20 already renamed tactics).
- *Use the TAXII server at runtime:* violates the offline guarantee.

## Consequences

- ATT&CK version is visible in `escalint version` and `analysis.json`
  (`catalogs.attack`).
- Mappings reflect our judgment on documented technique text; each mapping is
  justified in `docs/research.md` §13 with a quote.
- `escalint attack coverage` can state honestly which IaaS techniques the tool
  covers and which it does not.
