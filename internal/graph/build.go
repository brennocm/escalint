package graph

import (
	"sort"
	"strings"
	"time"

	"github.com/brennocm/escalint/internal/arn"
	"github.com/brennocm/escalint/internal/eval"
	"github.com/brennocm/escalint/internal/match"
	"github.com/brennocm/escalint/internal/snapshot"
)

// StaleAfter is how long without use makes a role stale.
const StaleAfter = 90 * 24 * time.Hour

// Rule metadata of the edges this package adds itself. The rule registry
// (internal/rules) describes the same IDs.
const (
	RuleAssume      = "EL-PE-014"
	PathfindingSTS1 = "sts-001"
)

// Options controls graph construction.
type Options struct {
	// Now is the reference time for staleness when the snapshot has no
	// collection time. Zero means time.Now().
	Now time.Time
}

// Build creates nodes, structural edges, trust and assume edges, and the
// admin edges of Tier 0 principals. Rules add the other escalation edges.
func Build(snap *snapshot.Snapshot, opts Options) (*Graph, *Env) {
	g := New()
	env := newEnv(snap)
	now := snap.CollectedAt
	if now.IsZero() {
		now = opts.Now
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	for _, acct := range snap.Accounts {
		g.AddNode(&Node{Kind: NodeTier0Sink, Key: SinkKey(acct.ID), Name: "Effective admin", Account: acct.ID})
		for _, grp := range acct.Groups {
			n := g.AddNode(&Node{Kind: NodeGroup, Key: grp.ARN, ARN: grp.ARN, Name: grp.Name, Account: acct.ID, Path: grp.Path})
			env.addGroup(n.ID, acct, grp)
		}
		for _, u := range acct.Users {
			n := g.AddNode(&Node{Kind: NodeUser, Key: u.ARN, ARN: u.ARN, Name: u.Name, Account: acct.ID, Path: u.Path, Tags: tagMap(u.Tags)})
			if u.PermissionsBoundary == "" {
				n.Flags = append(n.Flags, "no_boundary")
			}
			env.addUser(n.ID, acct, u)
			for _, grp := range u.Groups {
				g.AddEdge(&Edge{From: n.ID, To: NodeID(grp.ARN), Kind: EdgeMemberOf, Status: StatusAllowed})
			}
		}
		for _, r := range acct.Roles {
			n := g.AddNode(&Node{Kind: NodeRole, Key: r.ARN, ARN: r.ARN, Name: r.Name, Account: acct.ID, Path: r.Path, Tags: tagMap(r.Tags), LastUsed: r.LastUsed})
			if r.PermissionsBoundary == "" {
				n.Flags = append(n.Flags, "no_boundary")
			}
			if r.ServiceLinked {
				n.Flags = append(n.Flags, "service_linked")
			}
			if r.LastUsed != nil && now.Sub(*r.LastUsed) > StaleAfter {
				n.Flags = append(n.Flags, "stale")
			}
			env.addRole(n.ID, acct, r)
		}
	}

	addTrustEdges(g, env)
	addAssumeEdges(g, env)
	markTier0(g, env)
	for _, n := range g.Nodes() {
		sort.Strings(n.Flags)
	}
	return g, env
}

// SinkKey is the canonical key of an account's tier0 sink.
func SinkKey(account string) string { return "tier0:" + account }

func tagMap(tags []snapshot.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[t.Key] = t.Value
	}
	return m
}

// pseudoPrincipal is a principal named in a trust policy that is not an IAM
// user or role of the snapshot.
type pseudoPrincipal struct {
	node   *Node
	pr     *eval.Principal
	action string
}

// addTrustEdges creates nodes for services, external accounts, federated
// providers and "any principal" found in trust policies, and a trust edge
// when the trust (with RCPs) lets them assume the role.
func addTrustEdges(g *Graph, env *Env) {
	for _, role := range rolesOf(g) {
		tr := env.trust[role.ID]
		if tr == nil || tr.Doc == nil {
			continue
		}
		for _, pp := range pseudoPrincipals(g, env, tr) {
			res := env.Ask(pp.pr, pp.action, role.ARN, role.Account, role.ID, nil)
			if !res.Decision.Allowed() {
				continue
			}
			g.AddEdge(&Edge{
				From: pp.node.ID, To: role.ID, Kind: EdgeTrust, Status: StatusOf(res.Decision),
				RequiredActions: []string{pp.action}, ConditionsUnevaluated: res.Unevaluated,
				Evidence: EvidenceFrom(role.ID, pp.action, res),
			})
			if pp.node.Kind != NodeService {
				role.Flags = appendOnce(role.Flags, "external_trust")
			}
		}
	}
}

func pseudoPrincipals(g *Graph, env *Env, tr *eval.Policy) []pseudoPrincipal {
	var out []pseudoPrincipal
	seen := map[string]bool{}
	add := func(n *Node, pr *eval.Principal, action string) {
		n = g.AddNode(n)
		if seen[n.ID+action] {
			return
		}
		seen[n.ID+action] = true
		out = append(out, pseudoPrincipal{node: n, pr: pr, action: action})
	}
	for _, st := range tr.Doc.Statements {
		p := st.Principal
		if st.Effect != "Allow" || p == nil {
			continue
		}
		if p.Wildcard {
			add(&Node{Kind: NodeAnyPrincipal, Key: "any_principal", Name: "*"}, &eval.Principal{Kind: eval.PrincipalAnonymous}, "sts:AssumeRole")
		}
		for _, entry := range p.AWS {
			if entry == "*" {
				add(&Node{Kind: NodeAnyPrincipal, Key: "any_principal", Name: "*"}, &eval.Principal{Kind: eval.PrincipalAnonymous}, "sts:AssumeRole")
				continue
			}
			account := entryAccount(entry)
			if account != "" && !env.InSnapshot(account) {
				add(&Node{Kind: NodeExternalAccount, Key: "account:" + account, Name: account, Account: account},
					&eval.Principal{Kind: eval.PrincipalExternal, Account: account}, "sts:AssumeRole")
			}
		}
		for _, svc := range p.Service {
			add(&Node{Kind: NodeService, Key: "service:" + svc, Name: svc}, &eval.Principal{Kind: eval.PrincipalService, Name: svc}, "sts:AssumeRole")
		}
		for _, fed := range p.Federated {
			action := "sts:AssumeRoleWithWebIdentity"
			if strings.Contains(fed, ":saml-provider/") {
				action = "sts:AssumeRoleWithSAML"
			}
			account := ""
			if a, err := arn.Parse(fed); err == nil {
				account = a.Account
			}
			add(&Node{Kind: NodeFederated, Key: "federated:" + fed, ARN: fed, Name: federatedName(fed), Account: account},
				&eval.Principal{Kind: eval.PrincipalFederated, ARN: fed, Name: fed}, action)
		}
	}
	return out
}

func federatedName(fed string) string {
	if i := strings.Index(fed, "provider/"); i >= 0 {
		return fed[i+len("provider/"):]
	}
	return fed
}

// entryAccount returns the account of an AWS principal entry (account ID or
// ARN), or "" for unique IDs and malformed entries.
func entryAccount(entry string) string {
	if arn.IsAccountID(entry) {
		return entry
	}
	if a, err := arn.Parse(entry); err == nil && arn.IsAccountID(a.Account) {
		return a.Account
	}
	return ""
}

// addAssumeEdges adds X → role edges for IAM principals of the snapshot.
// Candidates come from the trust policy so the work stays proportional to
// what trusts actually name: the principal's ARN or unique ID, its account
// (only if X has some identity statement that may allow sts:AssumeRole), or
// "*" (everyone).
func addAssumeEdges(g *Graph, env *Env) {
	byARN, byID := map[string]*Node{}, map[string]*Node{}
	byAccount := map[string][]*Node{}
	var everyone []*Node
	for _, n := range g.Nodes() {
		if n.Kind != NodeUser && n.Kind != NodeRole {
			continue
		}
		byARN[n.ARN] = n
		if pr := env.Principal(n.ID); pr != nil && pr.ID != "" {
			byID[pr.ID] = n
		}
		byAccount[n.Account] = append(byAccount[n.Account], n)
		everyone = append(everyone, n)
	}

	for _, role := range rolesOf(g) {
		tr := env.trust[role.ID]
		if tr == nil || tr.Doc == nil {
			continue
		}
		candidates := map[string]*Node{}
		for _, st := range tr.Doc.Statements {
			p := st.Principal
			if st.Effect != "Allow" || p == nil {
				continue
			}
			if p.Wildcard {
				for _, n := range everyone {
					candidates[n.ID] = n
				}
			}
			for _, entry := range p.AWS {
				switch {
				case entry == "*":
					for _, n := range everyone {
						candidates[n.ID] = n
					}
				case byARN[entry] != nil:
					candidates[byARN[entry].ID] = byARN[entry]
				case byID[entry] != nil:
					candidates[byID[entry].ID] = byID[entry]
				default:
					account := entryAccount(entry)
					if account == "" || strings.Contains(entry, ":user/") || strings.Contains(entry, ":role/") {
						continue // a specific principal that is not in the snapshot
					}
					for _, n := range byAccount[account] {
						if mayAllow(env.Principal(n.ID), "sts:AssumeRole") {
							candidates[n.ID] = n
						}
					}
				}
			}
		}
		ids := make([]string, 0, len(candidates))
		for id := range candidates {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if id == role.ID {
				continue // a role assuming itself gains nothing
			}
			n := candidates[id]
			res := env.Ask(env.Principal(n.ID), "sts:AssumeRole", role.ARN, role.Account, role.ID, nil)
			if !res.Decision.Allowed() {
				continue
			}
			g.AddEdge(&Edge{
				From: n.ID, To: role.ID, Kind: EdgeAssume, Status: StatusOf(res.Decision),
				RuleIDs: []string{RuleAssume}, PathfindingIDs: []string{PathfindingSTS1},
				RequiredActions: []string{"sts:AssumeRole"}, ConditionsUnevaluated: res.Unevaluated,
				Evidence: EvidenceFrom(n.ID, "sts:AssumeRole", res),
			})
		}
	}
}

// mayAllow is a cheap pre-filter: does any identity statement possibly allow
// the action (ignoring resources and conditions)? Unknown policies may.
func mayAllow(pr *eval.Principal, action string) bool {
	if pr == nil {
		return false
	}
	for _, p := range pr.Identity {
		if p.Doc == nil {
			return true
		}
		for i := range p.Doc.Statements {
			st := &p.Doc.Statements[i]
			if st.Effect != "Allow" {
				continue
			}
			patterns, negated := st.ActionPatterns()
			matched := false
			for _, pat := range patterns {
				if match.Action(pat, action) {
					matched = true
					break
				}
			}
			if matched != negated {
				return true
			}
		}
	}
	return false
}

func rolesOf(g *Graph) []*Node {
	var out []*Node
	for _, n := range g.Nodes() {
		if n.Kind == NodeRole {
			out = append(out, n)
		}
	}
	return out
}

func appendOnce(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// tier0Probe is one request of the Tier 0 probe set (ADR 0008).
type tier0Probe struct {
	action, resource string
}

// Tier0Probes returns the probe requests for an account: IAM permission
// management on fresh entity names (so path-scoped policies do not count)
// and one witness per sensitive data class.
func Tier0Probes(account string) []tier0Probe {
	iam := "arn:aws:iam::" + account + ":"
	return []tier0Probe{
		{"iam:AttachUserPolicy", iam + "user/escalint-probe"},
		{"iam:AttachRolePolicy", iam + "role/escalint-probe"},
		{"iam:AttachGroupPolicy", iam + "group/escalint-probe"},
		{"iam:PutUserPolicy", iam + "user/escalint-probe"},
		{"iam:PutRolePolicy", iam + "role/escalint-probe"},
		{"iam:PutGroupPolicy", iam + "group/escalint-probe"},
		{"iam:CreatePolicyVersion", iam + "policy/escalint-probe"},
		{"iam:UpdateAssumeRolePolicy", iam + "role/escalint-probe"},
		{"iam:CreateAccessKey", iam + "user/escalint-probe"},
		{"iam:PassRole", iam + "role/escalint-probe"},
		{"iam:DeleteRolePermissionsBoundary", iam + "role/escalint-probe"},
		{"iam:DeleteUserPermissionsBoundary", iam + "user/escalint-probe"},
		{"sts:AssumeRole", iam + "role/escalint-probe"},
		{"s3:GetObject", "arn:aws:s3:::escalint-probe/object"},
		{"kms:Decrypt", "arn:aws:kms:us-east-1:" + account + ":key/escalint-probe"},
		{"secretsmanager:GetSecretValue", "arn:aws:secretsmanager:us-east-1:" + account + ":secret:escalint-probe"},
		{"ec2:RunInstances", "arn:aws:ec2:us-east-1:" + account + ":instance/*"},
	}
}

// markTier0 evaluates the probe set for every user, role and group and adds
// an admin edge to the account sink for Tier 0 principals. Probes are
// identity-only questions (no trust policy), as ADR 0008 defines Tier 0 by
// what the principal's own policies let it do.
func markTier0(g *Graph, env *Env) {
	for _, n := range g.Nodes() {
		if n.Kind != NodeUser && n.Kind != NodeRole && n.Kind != NodeGroup {
			continue
		}
		pr := env.Principal(n.ID)
		decision := eval.Allow
		var unevaluated []string
		var evidence []Evidence
		for _, probe := range Tier0Probes(n.Account) {
			res := env.Ask(pr, probe.action, probe.resource, n.Account, "", nil)
			if !res.Decision.Allowed() {
				decision = res.Decision
				break
			}
			if res.Decision == eval.Conditional {
				decision = eval.Conditional
				unevaluated = append(unevaluated, res.Unevaluated...)
			}
			if probe.action == "iam:PutRolePolicy" {
				evidence = EvidenceFrom(n.ID, probe.action, res)
			}
		}
		if !decision.Allowed() {
			n.Tier = 3 // refined by the tier analysis
			continue
		}
		n.Tier = 0
		n.TierConditional = decision == eval.Conditional
		g.AddEdge(&Edge{
			From: n.ID, To: NodeID(SinkKey(n.Account)), Kind: EdgeAdmin, Status: StatusOf(decision),
			ConditionsUnevaluated: unevaluated, Evidence: evidence,
		})
	}
}
