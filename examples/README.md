# Example accounts

Two synthetic snapshots (fake account IDs) that are also permanent
integration tests (`internal/engine/examples_test.go`).

| Example | What it shows |
| --- | --- |
| [`vulnerable-account`](vulnerable-account/) | One scenario per stable rule: every `EL-PE`, `EL-TR` and `EL-PARSE` rule that is not experimental fires at least once. Entity names start with the rule they illustrate (`pe022-attacker`, `tr002-ci-deploy`). |
| [`hardened-account`](hardened-account/) | The same kinds of identities done right: least privilege, a permissions boundary for developers, GitHub Actions OIDC pinned to one repository and environment, a vendor role with `sts:ExternalId`, an allowlisted security account. Zero findings; the only path to Tier 0 is the intended single sign-on into the admin role. |

Try them:

```sh
escalint scan examples/vulnerable-account/snapshot.json --config-file examples/vulnerable-account/.escalint.yaml
escalint scan examples/hardened-account/snapshot.json --config-file examples/hardened-account/.escalint.yaml
escalint serve examples/vulnerable-account/snapshot.json
```
