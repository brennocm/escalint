package graph

import (
	"strings"

	"github.com/brennocm/escalint/internal/eval"
	"github.com/brennocm/escalint/internal/snapshot"
)

// Env turns snapshot entities into evaluator inputs and answers
// authorization questions about graph nodes.
type Env struct {
	Snap  *snapshot.Snapshot
	OrgID string // analyzed organization, "" without organization data

	accounts   map[string]*snapshot.Account
	principals map[string]*eval.Principal // node ID -> principal
	trust      map[string]*eval.Policy    // role node ID -> trust policy
	nodeAcct   map[string]string          // node ID -> account
	notes      []string
}

// Notes explains global modeling choices (for example missing SCPs).
func (e *Env) Notes() []string { return e.notes }

// Principal returns the evaluator view of a user, role or group node.
func (e *Env) Principal(nodeID string) *eval.Principal { return e.principals[nodeID] }

// InSnapshot reports whether the account was analyzed.
func (e *Env) InSnapshot(account string) bool { return e.accounts[account] != nil }

func newEnv(snap *snapshot.Snapshot) *Env {
	env := &Env{
		Snap:       snap,
		accounts:   map[string]*snapshot.Account{},
		principals: map[string]*eval.Principal{},
		trust:      map[string]*eval.Policy{},
		nodeAcct:   map[string]string{},
	}
	for _, a := range snap.Accounts {
		env.accounts[a.ID] = a
	}
	if snap.Organization != nil {
		env.OrgID = snap.Organization.ID
		if !hasPolicies(snap.Organization, snapshot.PolicySCP) {
			env.notes = append(env.notes, "the organization has no SCPs in the snapshot; SCPs are not evaluated")
		}
	}
	return env
}

func hasPolicies(org *snapshot.Organization, t snapshot.PolicyType) bool {
	for _, p := range org.Policies {
		if p.Type == t {
			return true
		}
	}
	return false
}

// orgChain builds the SCP or RCP chain of an account: nil when there is no
// organization data, the account is the management account, the account is
// not in the tree, or the organization has no policies of that type.
func (e *Env) orgChain(account string, t snapshot.PolicyType) *eval.OrgChain {
	org := e.Snap.Organization
	if org == nil || account == org.ManagementAccountID || !hasPolicies(org, t) {
		return nil
	}
	path, err := org.PathTo(account)
	if err != nil {
		return nil
	}
	ptype := eval.TypeSCP
	if t == snapshot.PolicyRCP {
		ptype = eval.TypeRCP
	}
	chain := &eval.OrgChain{}
	for _, nodeID := range path {
		var level []eval.Policy
		for _, p := range org.PoliciesAttachedTo(nodeID, t) {
			level = append(level, eval.Policy{Type: ptype, Source: p.ID, Name: p.Name, Doc: p.Document})
		}
		chain.Levels = append(chain.Levels, level)
	}
	return chain
}

func (e *Env) orgIDFor(account string) string {
	org := e.Snap.Organization
	if org == nil {
		return ""
	}
	if _, err := org.PathTo(account); err == nil {
		return org.ID
	}
	return ""
}

func managedPolicy(acct *snapshot.Account, arn string, t eval.PolicyType) eval.Policy {
	p := eval.Policy{Type: t, Source: arn, Name: arn[strings.LastIndex(arn, "/")+1:]}
	if mp := acct.Policy(arn); mp != nil {
		p.Name = mp.Name
		p.Doc = mp.Document
	}
	return p
}

func inlinePolicies(owner string, list []snapshot.InlinePolicy) []eval.Policy {
	out := make([]eval.Policy, 0, len(list))
	for _, ip := range list {
		out = append(out, eval.Policy{Type: eval.TypeIdentity, Source: "inline:" + owner + "/" + ip.Name, Name: ip.Name, Doc: ip.Document})
	}
	return out
}

func (e *Env) boundary(acct *snapshot.Account, arn string) *eval.Policy {
	if arn == "" {
		return nil
	}
	p := managedPolicy(acct, arn, eval.TypeBoundary)
	return &p
}

func (e *Env) addUser(nodeID string, acct *snapshot.Account, u *snapshot.User) {
	pr := &eval.Principal{Kind: eval.PrincipalUser, ARN: u.ARN, ID: u.ID, Account: acct.ID}
	pr.Identity = append(pr.Identity, inlinePolicies(u.ARN, u.Inline)...)
	for _, a := range u.Attached {
		pr.Identity = append(pr.Identity, managedPolicy(acct, a, eval.TypeIdentity))
	}
	for _, g := range u.Groups {
		pr.Identity = append(pr.Identity, inlinePolicies(g.ARN, g.Inline)...)
		for _, a := range g.Attached {
			pr.Identity = append(pr.Identity, managedPolicy(acct, a, eval.TypeIdentity))
		}
	}
	pr.Boundary = e.boundary(acct, u.PermissionsBoundary)
	e.finishPrincipal(nodeID, pr)
}

func (e *Env) addRole(nodeID string, acct *snapshot.Account, r *snapshot.Role) {
	pr := &eval.Principal{Kind: eval.PrincipalRole, ARN: r.ARN, ID: r.ID, Account: acct.ID, ServiceLinked: r.ServiceLinked}
	pr.Identity = append(pr.Identity, inlinePolicies(r.ARN, r.Inline)...)
	for _, a := range r.Attached {
		pr.Identity = append(pr.Identity, managedPolicy(acct, a, eval.TypeIdentity))
	}
	pr.Boundary = e.boundary(acct, r.PermissionsBoundary)
	e.finishPrincipal(nodeID, pr)
	e.trust[nodeID] = &eval.Policy{Type: eval.TypeResource, Source: "trust:" + r.ARN, Name: "trust policy", Doc: r.Trust}
}

// addGroup models a group as the permissions a new member gains. Its ARN
// stands in for the member's, so conditions on aws:PrincipalArn are judged
// against the group (an approximation recorded in docs/research.md §6).
func (e *Env) addGroup(nodeID string, acct *snapshot.Account, g *snapshot.Group) {
	pr := &eval.Principal{Kind: eval.PrincipalUser, ARN: g.ARN, ID: g.ID, Account: acct.ID}
	pr.Identity = append(pr.Identity, inlinePolicies(g.ARN, g.Inline)...)
	for _, a := range g.Attached {
		pr.Identity = append(pr.Identity, managedPolicy(acct, a, eval.TypeIdentity))
	}
	e.finishPrincipal(nodeID, pr)
}

func (e *Env) finishPrincipal(nodeID string, pr *eval.Principal) {
	if !pr.ServiceLinked {
		pr.SCPs = e.orgChain(pr.Account, snapshot.PolicySCP)
	}
	pr.OrgID = e.orgIDFor(pr.Account)
	e.principals[nodeID] = pr
	e.nodeAcct[nodeID] = pr.Account
}

// Ask evaluates an action by the principal of node `from` on a resource.
// For roles in the snapshot pass the role's node ID as resourceNode so its
// trust policy and RCPs apply; otherwise pass "".
func (e *Env) Ask(from *eval.Principal, action, resourceARN, resourceAccount, resourceNode string, ctx map[string][]string) eval.Result {
	res := &eval.Resource{ARN: resourceARN, Account: resourceAccount}
	if resourceNode != "" {
		res.Policy = e.trust[resourceNode]
	}
	if resourceAccount != "" && eval.RCPApplies(action) {
		res.RCPs = e.orgChain(resourceAccount, snapshot.PolicyRCP)
	}
	if ctx == nil {
		ctx = eval.NewContext(from, e.OrgID)
	}
	return eval.Evaluate(&eval.Request{Principal: from, Action: action, Resource: res, Context: ctx})
}

// EvidenceFrom converts the allowing statements of a result into evidence.
func EvidenceFrom(principalNode, action string, r eval.Result) []Evidence {
	var out []Evidence
	for _, s := range r.Steps {
		if s.Effect != "Allow" || s.Stage == eval.TypeSCP || s.Stage == eval.TypeRCP {
			continue
		}
		out = append(out, Evidence{
			Principal: principalNode, Action: action, Policy: s.Policy, Statement: s.Statement,
			Sid: s.Sid, Effect: string(s.Effect), Stage: string(s.Stage),
		})
	}
	return out
}

// StatusOf maps an allowed decision to an edge status.
func StatusOf(d eval.Decision) Status {
	if d == eval.Allow {
		return StatusAllowed
	}
	return StatusConditional
}
