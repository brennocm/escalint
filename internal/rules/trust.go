package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/policy"
)

// Trust rules (EL-TR-*) look at who a role's trust policy admits from
// outside the analyzed accounts. They report findings directly, on roles
// whose trust edge from that principal exists: the evaluator already
// applied deny statements, RCPs and the condition keys it understands, so
// a trust that is restricted by aws:PrincipalOrgID, for example, produces
// no edge and no finding.

// githubOIDC is the GitHub Actions OIDC provider host.
const githubOIDC = "token.actions.githubusercontent.com"

type trustRule struct {
	meta  Metadata
	check func(ctx *Context, t trustCase) (string, bool)
	kinds []graph.NodeKind // pseudo-principal kinds the rule inspects
}

// trustCase is one (outside principal, role) pair with an existing trust
// edge and the trust statements that name the principal.
type trustCase struct {
	from       *graph.Node
	role       *graph.Node
	edge       *graph.Edge
	statements []policy.Statement
}

func (r trustRule) Meta() Metadata { return r.meta }
func (r trustRule) Pass() Pass     { return PassPrimitive }

func (r trustRule) Apply(ctx *Context) []Finding {
	var out []Finding
	for _, e := range ctx.Graph.Edges() {
		if e.Kind != graph.EdgeTrust {
			continue
		}
		from, role := ctx.Graph.Node(e.From), ctx.Graph.Node(e.To)
		if from == nil || role == nil || !slices.Contains(r.kinds, from.Kind) {
			continue
		}
		tr := ctx.Env.TrustPolicy(role.ID)
		if tr == nil || tr.Doc == nil {
			continue
		}
		tc := trustCase{from: from, role: role, edge: e, statements: naming(tr.Doc, from)}
		if len(tc.statements) == 0 {
			continue
		}
		msg, ok := r.check(ctx, tc)
		if !ok {
			continue
		}
		if e.Status == graph.StatusConditional {
			msg += fmt.Sprintf(" (conditional: %s not evaluated)", strings.Join(e.ConditionsUnevaluated, ", "))
		}
		out = append(out, Finding{
			RuleID: r.meta.ID, Severity: r.meta.Severity, NodeID: role.ID, EdgeID: e.ID, Title: r.meta.Title,
			Message: msg,
			Location: Location{
				Account: role.Account, Entity: role.ARN, Policy: "trust:" + role.ARN,
				Statement: tc.statements[0].Index,
			},
		})
	}
	return out
}

// naming returns the Allow statements of a trust policy that admit the
// pseudo-principal.
func naming(doc *policy.Document, from *graph.Node) []policy.Statement {
	var out []policy.Statement
	for _, st := range doc.Statements {
		p := st.Principal
		if st.Effect != policy.Allow || p == nil {
			continue
		}
		switch from.Kind {
		case graph.NodeAnyPrincipal:
			if p.Wildcard || slices.Contains(p.AWS, "*") {
				out = append(out, st)
			}
		case graph.NodeExternalAccount:
			for _, entry := range p.AWS {
				if entry == from.Account || strings.HasPrefix(entry, "arn:aws:iam::"+from.Account+":") ||
					strings.Contains(entry, "::"+from.Account+":") {
					out = append(out, st)
					break
				}
			}
		case graph.NodeFederated:
			if slices.Contains(p.Federated, from.ARN) {
				out = append(out, st)
			}
		case graph.NodeUser, graph.NodeRole, graph.NodeGroup, graph.NodeService, graph.NodeTier0Sink:
		}
	}
	return out
}

// conditionValues returns the values of every clause on key (keys compare
// case-insensitively, as in IAM) and whether any clause names it.
func conditionValues(st policy.Statement, key string) ([]string, bool) {
	var out []string
	found := false
	for _, c := range st.Condition {
		if strings.EqualFold(c.Key, key) {
			found = true
			out = append(out, c.Values...)
		}
	}
	return out, found
}

func allHave(sts []policy.Statement, key string) bool {
	for _, st := range sts {
		if _, ok := conditionValues(st, key); !ok {
			return false
		}
	}
	return true
}

// BroadGitHubSubject reports whether a GitHub Actions `sub` pattern admits
// more than one repository or any ref of a repository: "*", "repo:*",
// "repo:<org>/*" or "repo:<org>/<repo>" with nothing or "*" after it.
func BroadGitHubSubject(sub string) bool {
	rest, ok := strings.CutPrefix(sub, "repo:")
	if !ok {
		return sub == "*" || strings.HasPrefix(sub, "*")
	}
	repo, qualifier, _ := strings.Cut(rest, ":")
	org, name, hasName := strings.Cut(repo, "/")
	if org == "" || strings.Contains(org, "*") || !hasName || name == "" || strings.Contains(name, "*") {
		return true
	}
	return qualifier == "" || qualifier == "*"
}

func elTR001() Rule {
	return trustRule{
		kinds: []graph.NodeKind{graph.NodeAnyPrincipal},
		check: func(_ *Context, t trustCase) (string, bool) {
			// A condition on who the caller is restricts the wildcard even
			// when the evaluator cannot decide it (no organization data).
			for _, st := range t.statements {
				restricted := false
				for _, key := range []string{"aws:PrincipalOrgID", "aws:PrincipalAccount", "aws:PrincipalArn", "aws:PrincipalOrgPaths"} {
					if _, ok := conditionValues(st, key); ok {
						restricted = true
					}
				}
				if !restricted {
					return fmt.Sprintf("the trust policy of %s lets any AWS principal assume it", t.role.ARN), true
				}
			}
			return "", false
		},
		meta: Metadata{
			ID: "EL-TR-001", Title: "Role trusts any AWS principal", Category: TrustCategory, Severity: Critical, Status: Stable,
			RequiredActions: []string{"sts:AssumeRole"},
			Attack:          []string{"T1078.004"},
			Remediation:     `Name the accounts or roles that may assume the role in "Principal", or add a condition on aws:PrincipalOrgID, aws:PrincipalAccount or aws:PrincipalArn.`,
			References: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html",
				"https://cwe.mitre.org/data/definitions/284.html",
			},
		},
	}
}

func elTR002() Rule {
	return trustRule{
		kinds: []graph.NodeKind{graph.NodeFederated},
		check: func(_ *Context, t trustCase) (string, bool) {
			if !strings.HasSuffix(t.from.ARN, ":oidc-provider/"+githubOIDC) || allHave(t.statements, githubOIDC+":sub") {
				return "", false
			}
			return fmt.Sprintf("any GitHub Actions workflow, in any repository, can assume %s: the trust has no condition on %s:sub", t.role.ARN, githubOIDC), true
		},
		meta: Metadata{
			ID: "EL-TR-002", Title: "GitHub Actions OIDC trust without a sub condition", Category: TrustCategory, Severity: Critical, Status: Stable,
			RequiredActions: []string{"sts:AssumeRoleWithWebIdentity"},
			Attack:          []string{"T1199", "T1078.004"},
			Remediation:     `Add "Condition": {"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:<org>/<repo>:ref:refs/heads/main"}} (or an environment) together with the aud condition.`,
			References: []string{
				"https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services",
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html",
				"https://cwe.mitre.org/data/definitions/284.html",
			},
		},
	}
}

func elTR003() Rule {
	return trustRule{
		kinds: []graph.NodeKind{graph.NodeFederated},
		check: func(_ *Context, t trustCase) (string, bool) {
			if !strings.HasSuffix(t.from.ARN, ":oidc-provider/"+githubOIDC) {
				return "", false
			}
			var broad []string
			for _, st := range t.statements {
				values, ok := conditionValues(st, githubOIDC+":sub")
				if !ok {
					return "", false // EL-TR-002 reports it
				}
				for _, v := range values {
					if BroadGitHubSubject(v) {
						broad = append(broad, v)
					}
				}
			}
			if len(broad) == 0 {
				return "", false
			}
			slices.Sort(broad)
			return fmt.Sprintf("the GitHub Actions trust of %s accepts broad subjects: %s", t.role.ARN, strings.Join(slices.Compact(broad), ", ")), true
		},
		meta: Metadata{
			ID: "EL-TR-003", Title: "GitHub Actions OIDC trust with a broad sub pattern", Category: TrustCategory, Severity: High, Status: Stable,
			RequiredActions: []string{"sts:AssumeRoleWithWebIdentity"},
			Attack:          []string{"T1199", "T1078.004"},
			Remediation:     `Pin the sub condition to one repository and a branch, tag or environment, for example "repo:<org>/<repo>:environment:production"; avoid wildcards in the organization or repository part.`,
			References: []string{
				"https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
				"https://cwe.mitre.org/data/definitions/284.html",
			},
		},
	}
}

func elTR004() Rule {
	return trustRule{
		kinds: []graph.NodeKind{graph.NodeExternalAccount},
		check: func(ctx *Context, t trustCase) (string, bool) {
			if slices.Contains(ctx.Config.TrustedAccounts, t.from.Account) || slices.Contains(ctx.Config.ThirdPartyAccounts, t.from.Account) {
				return "", false
			}
			return fmt.Sprintf("%s trusts account %s, which is neither analyzed nor listed in trusted_accounts", t.role.ARN, t.from.Account), true
		},
		meta: Metadata{
			ID: "EL-TR-004", Title: "Trust to an external account outside the allowlist", Category: TrustCategory, Severity: Medium, Status: Stable,
			RequiredActions: []string{"sts:AssumeRole"},
			Attack:          []string{"T1199"},
			Remediation:     "Confirm the account belongs to your organization or a vendor; add it to trusted_accounts or third_party_accounts in .escalint.yaml, or remove it from the trust policy.",
			References: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_aws-accounts.html",
				"https://cwe.mitre.org/data/definitions/284.html",
			},
		},
	}
}

func elTR005() Rule {
	return trustRule{
		kinds: []graph.NodeKind{graph.NodeExternalAccount},
		check: func(ctx *Context, t trustCase) (string, bool) {
			if !slices.Contains(ctx.Config.ThirdPartyAccounts, t.from.Account) || allHave(t.statements, "sts:ExternalId") {
				return "", false
			}
			return fmt.Sprintf("third-party account %s can assume %s without an sts:ExternalId condition (confused deputy)", t.from.Account, t.role.ARN), true
		},
		meta: Metadata{
			ID: "EL-TR-005", Title: "Third-party trust without sts:ExternalId", Category: TrustCategory, Severity: High, Status: Stable,
			RequiredActions: []string{"sts:AssumeRole"},
			Attack:          []string{"T1199"},
			Remediation:     `Add "Condition": {"StringEquals": {"sts:ExternalId": "<value the vendor gave you>"}} to the statement that trusts the vendor account.`,
			References: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html",
				"https://cwe.mitre.org/data/definitions/441.html",
			},
		},
	}
}

func elTR006() Rule {
	return trustRule{
		kinds: []graph.NodeKind{graph.NodeFederated},
		check: func(_ *Context, t trustCase) (string, bool) {
			arn := t.from.ARN
			switch {
			case strings.HasSuffix(arn, ":oidc-provider/"+githubOIDC):
				return "", false // EL-TR-002/003
			case strings.Contains(arn, ":saml-provider/"):
				if allHave(t.statements, "SAML:aud") {
					return "", false
				}
				return fmt.Sprintf("the SAML trust of %s has no SAML:aud condition", t.role.ARN), true
			case strings.Contains(arn, ":oidc-provider/"):
				host := arn[strings.Index(arn, ":oidc-provider/")+len(":oidc-provider/"):]
				if allHave(t.statements, host+":aud") || allHave(t.statements, host+":sub") {
					return "", false
				}
				return fmt.Sprintf("the OIDC trust of %s for %s has no condition on %s:aud or %s:sub", t.role.ARN, host, host, host), true
			}
			return "", false
		},
		meta: Metadata{
			ID: "EL-TR-006", Title: "OIDC or SAML trust without an audience or subject condition", Category: TrustCategory, Severity: Medium, Status: Experimental,
			RequiredActions: []string{"sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML"},
			Attack:          []string{"T1199", "T1078.004"},
			Remediation:     "Add a condition on the provider's aud (and sub for OIDC) keys, or SAML:aud for SAML, so only the intended application and identities can assume the role.",
			References: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html",
				"https://cwe.mitre.org/data/definitions/284.html",
			},
		},
	}
}
