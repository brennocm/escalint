# Third-party notices

escalint embeds or derives data from the following projects. Their licenses
apply to the corresponding files.

## MITRE ATT&CK®

- Files: `internal/attack/data/attack.json` (technique IDs, names, tactics and
  URLs extracted from Enterprise ATT&CK v20.0, STIX bundle
  `enterprise-attack-20.0.json`).
- License: `internal/attack/data/LICENSE-MITRE.txt`.
- Notice: © 2026 The MITRE Corporation. This work is reproduced and
  distributed with the permission of The MITRE Corporation.
- MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.
  escalint is not affiliated with or endorsed by MITRE.

## pathfinding.cloud (Datadog)

- Use: rule metadata references pathfinding.cloud path IDs and links
  (`https://pathfinding.cloud`); descriptions are written for escalint.
- License: Apache License 2.0. NOTICE of the project:
  "Datadog pathfinding.cloud. Copyright 2025-Present Datadog, Inc. This
  product includes software developed at Datadog (https://www.datadoghq.com/)."
- escalint is not affiliated with or endorsed by Datadog.

## AWS service reference information

- Files: `internal/catalog/data/catalog.json.gz`, derived from the
  machine-readable service reference published by AWS
  (https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html).
- escalint is not affiliated with or endorsed by Amazon Web Services.

## SARIF 2.1.0 JSON schema (test data only)

- File: `internal/report/testdata/sarif-2.1.0.json`, the OASIS SARIF 2.1.0
  schema as distributed by SchemaStore (Apache License 2.0). Used only by
  tests to validate SARIF output; not embedded in the binary.

## Fonts

- Inter (`web/src/assets/fonts/InterVariable-latin.woff2`): SIL Open Font
  License 1.1, `web/src/assets/fonts/Inter-LICENSE.txt`.
- JetBrains Mono (`web/src/assets/fonts/JetBrainsMonoVariable-latin.woff2`):
  SIL Open Font License 1.1, `web/src/assets/fonts/JetBrainsMono-LICENSE.txt`.
- Both are latin subsets of the original files; neither license declares a
  Reserved Font Name.
