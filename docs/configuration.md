# Configuration: `.escalint.yaml`

escalint reads `.escalint.yaml` from the working directory, or the file given
with `--config-file`. Every key is optional except `version`. Unknown keys,
YAML anchors and aliases are errors; the file may be at most 1 MiB.

```yaml
version: 1

# Accounts outside the snapshot that are part of your estate (EL-TR-004 does
# not report trusts to them).
trusted_accounts:
  - "222222222222"

# Vendors: trusts to them must use sts:ExternalId (EL-TR-005).
third_party_accounts:
  - "999999999999"

# Suppressions hide findings of one rule (ID or glob) on principals whose ARN
# matches a glob. A reason is mandatory; expires is optional (inclusive).
suppressions:
  - rule: EL-TR-004
    arn: "arn:aws:iam::111111111111:role/legacy-partner-*"
    reason: "Partner integration approved by the security team (SEC-1234)"
    expires: 2027-01-31

# Groupings name sets of principals for the UI.
groupings:
  - name: payments
    arns: ["arn:aws:iam::*:role/payments-*", "arn:aws:iam::*:user/pay-*"]

# Defaults for rule selection; command-line flags add to them.
rules:
  enable: [EL-PE-026]
  disable: [EL-TR-006]
  experimental: false

# Defaults for scan.
fail_on: high        # critical | high | medium | low | info | none
min_severity: info
```

## Suppressions

- `rule` matches the rule ID with `*` and `?` wildcards (`EL-TR-*`).
- `arn` matches the finding's subject: the principal the finding is about
  (for path rules the principal that escalates, for trust rules the role).
- Suppressed findings are **never removed**: they appear in JSON
  (`findings[].suppressed`), SARIF (`results[].suppressions`) and the UI,
  and the top-level `suppressions[]` lists every entry with its status and
  the findings it matched. They do not count towards `--fail-on`.
- Without a `reason` the entry has status `unjustified`, suppresses nothing,
  and produces an `EL-PARSE-003` finding.
- After `expires` the entry has status `expired` and its findings are
  reported again.

## Groupings

The first grouping whose patterns match a principal's ARN is shown in the UI
(`nodes[].group`) and listed in `groupings[]`.
