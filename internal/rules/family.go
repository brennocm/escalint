package rules

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/brennocm/escalint/internal/eval"
	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/policy"
	"github.com/brennocm/escalint/internal/snapshot"
)

// Building blocks shared by the rule families. Every family follows the same
// template (docs/research.md §7): for each candidate (actor, target) pair,
// evaluate every required action on the resource it authorizes; the edge
// exists if all are allowed, and its status is the weakest result.

// check is the combined outcome of several evaluations.
type check struct {
	ok          bool
	conditional bool
	unevaluated []string
	evidence    []graph.Evidence
}

func (c *check) add(actorID, action string, r eval.Result) {
	if !r.Decision.Allowed() {
		c.ok = false
		return
	}
	if r.Decision == eval.Conditional {
		c.conditional = true
		c.unevaluated = append(c.unevaluated, r.Unevaluated...)
	}
	c.evidence = append(c.evidence, graph.EvidenceFrom(actorID, action, r)...)
}

func newCheck() *check { return &check{ok: true} }

func (c *check) status() graph.Status {
	if c.conditional {
		return graph.StatusConditional
	}
	return graph.StatusAllowed
}

// actors returns the IAM nodes (users, roles, groups) that may act, skipping
// Tier 0 principals (already admin) and principals with no statement that
// could allow the first required action (cheap pre-filter).
func actors(ctx *Context, firstAction string, kinds ...graph.NodeKind) []*graph.Node {
	var out []*graph.Node
	for _, n := range ctx.Graph.Nodes() {
		if n.Tier == 0 || !kindIn(n.Kind, kinds) {
			continue
		}
		if graph.MayAllow(ctx.Env.Principal(n.ID), firstAction) {
			out = append(out, n)
		}
	}
	return out
}

func kindIn(k graph.NodeKind, kinds []graph.NodeKind) bool {
	for _, x := range kinds {
		if x == k {
			return true
		}
	}
	return false
}

var iamActors = []graph.NodeKind{graph.NodeUser, graph.NodeRole, graph.NodeGroup}

func nodesOfKind(ctx *Context, kind graph.NodeKind) []*graph.Node {
	var out []*graph.Node
	for _, n := range ctx.Graph.Nodes() {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

func sinkOf(account string) string { return graph.NodeID(graph.SinkKey(account)) }

// edgeFor builds an edge carrying the rule metadata.
func edgeFor(m Metadata, from, to string, c *check, prereqs []string) *graph.Edge {
	status := c.status()
	if len(prereqs) > 0 {
		status = graph.StatusConditional
	}
	return &graph.Edge{
		From: from, To: to, Kind: m.EdgeKind, Status: status,
		RuleIDs: []string{m.ID}, PathfindingIDs: m.PathfindingIDs, RequiredActions: m.RequiredActions,
		Evidence: c.evidence, ConditionsUnevaluated: dedupe(c.unevaluated), PrerequisitesUnverified: prereqs,
	}
}

func dedupe(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, s := range list {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// askAll evaluates every action of the rule by actor on one resource.
func askAll(ctx *Context, actor *graph.Node, actions []string, resourceARN, resourceAccount string) *check {
	c := newCheck()
	pr := ctx.Env.Principal(actor.ID)
	if len(actions) > 0 && !graph.MayAllowOn(pr, actions[0], resourceARN) {
		c.ok = false // no identity statement can cover this resource
		return c
	}
	for _, a := range actions {
		c.add(actor.ID, a, ctx.Env.Ask(pr, a, resourceARN, resourceAccount, "", nil))
		if !c.ok {
			break
		}
	}
	return c
}

// ---------------------------------------------------------------------------
// Family: change one's own permissions (self-escalation). The edge goes
// straight to the actor account's sink.

type selfTarget func(ctx *Context, actor *graph.Node) []string // resource ARNs

type selfRule struct {
	meta    Metadata
	kinds   []graph.NodeKind
	targets selfTarget
}

func (r selfRule) Meta() Metadata { return r.meta }
func (r selfRule) Pass() Pass     { return PassPrimitive }

func (r selfRule) Apply(ctx *Context) []Finding {
	for _, actor := range actors(ctx, r.meta.RequiredActions[0], r.kinds...) {
		for _, target := range r.targets(ctx, actor) {
			c := askAll(ctx, actor, r.meta.RequiredActions, target, actor.Account)
			if c.ok {
				ctx.Graph.AddEdge(edgeFor(r.meta, actor.ID, sinkOf(actor.Account), c, boundaryCap(ctx, actor)))
				break
			}
		}
	}
	return nil
}

// adminDocument stands for whatever the actor writes into its own policies.
var adminDocument = sync.OnceValues(func() (*policy.Document, error) {
	return policy.Parse([]byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`), policy.KindIdentity, policy.Limits{})
})

// boundaryCap returns a prerequisite when the actor's permissions boundary
// (with its SCPs) would keep even an administrator policy below Tier 0: the
// boundary intersects whatever the actor grants itself. The edge is then
// conditional, not dropped: the actor may also be able to remove the
// boundary, or the boundary may grant enough for another path.
func boundaryCap(ctx *Context, actor *graph.Node) []string {
	pr := ctx.Env.Principal(actor.ID)
	if pr == nil || pr.Boundary == nil {
		return nil
	}
	doc, err := adminDocument()
	if err != nil {
		return nil // constant document; failing here keeps the edge allowed (over-report)
	}
	admin := *pr
	admin.Identity = []eval.Policy{{Type: eval.TypeIdentity, Source: "escalint:self-granted", Doc: doc}}
	if ctx.Env.PassesTier0Probes(&admin, actor.Account) {
		return nil
	}
	return []string{"the permissions boundary " + pr.Boundary.Source + " caps what the new policy grants: administrator only if the boundary is removed or allows it"}
}

func ownARN(_ *Context, actor *graph.Node) []string { return []string{actor.ARN} }

// attachedCustomerPolicies lists the customer managed policies attached to
// the actor (directly or through groups): CreatePolicyVersion on any of
// them rewrites the actor's own permissions.
func attachedCustomerPolicies(ctx *Context, actor *graph.Node) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range ctx.Env.Principal(actor.ID).Identity {
		if strings.HasPrefix(p.Source, "arn:") && strings.Contains(p.Source, ":"+actor.Account+":policy/") && !seen[p.Source] {
			seen[p.Source] = true
			out = append(out, p.Source)
		}
	}
	sort.Strings(out)
	return out
}

// groupsOf returns the group ARNs the actor user belongs to.
func groupsOf(ctx *Context, actor *graph.Node) []string {
	var out []string
	for _, e := range ctx.Graph.Out(actor.ID) {
		if e.Kind == graph.EdgeMemberOf {
			out = append(out, ctx.Graph.Node(e.To).ARN)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Family: act on another principal (credential, join group, modify trust).

// pairRule evaluates the actions on each target node and adds actor →
// target edges.
type pairRule struct {
	meta Metadata
	// targetKind selects the targets; the actor never targets itself.
	targetKind graph.NodeKind
	actorKinds []graph.NodeKind
	// prereqs returns unverified prerequisites for a pair, or skip=true when
	// a known fact rules the edge out.
	prereqs func(ctx *Context, actor, target *graph.Node) (unverified []string, skip bool)
	// afterwards optionally checks that the actor can use what it gained
	// (for example assume the role after rewriting its trust).
	afterwards func(ctx *Context, actor, target *graph.Node, c *check)
}

func (r pairRule) Meta() Metadata { return r.meta }
func (r pairRule) Pass() Pass     { return PassPrimitive }

func (r pairRule) Apply(ctx *Context) []Finding {
	targets := nodesOfKind(ctx, r.targetKind)
	index := make(map[string]int, len(targets))
	for i, t := range targets {
		index[t.ARN] = i
	}
	for _, actor := range actors(ctx, r.meta.RequiredActions[0], r.actorKinds...) {
		for _, target := range candidateTargets(ctx, actor, r.meta.RequiredActions[0], targets, index) {
			if target.ID == actor.ID {
				continue
			}
			var prereqs []string
			if r.prereqs != nil {
				var skip bool
				prereqs, skip = r.prereqs(ctx, actor, target)
				if skip {
					continue
				}
			}
			c := askAll(ctx, actor, r.meta.RequiredActions, target.ARN, target.Account)
			if c.ok && r.afterwards != nil {
				r.afterwards(ctx, actor, target, c)
			}
			if c.ok {
				ctx.Graph.AddEdge(edgeFor(r.meta, actor.ID, target.ID, c, prereqs))
			}
		}
	}
	return nil
}

// candidateTargets narrows targets to the ones the actor's statements name
// when they name exact ARNs only (the common, scoped case); askAll would
// reject every other target. Wildcards keep the full list. The order of
// targets is kept so the result stays deterministic.
func candidateTargets(ctx *Context, actor *graph.Node, action string, targets []*graph.Node, index map[string]int) []*graph.Node {
	exact, wide := graph.ExactResources(ctx.Env.Principal(actor.ID), action)
	if wide {
		return targets
	}
	picked := make([]int, 0, len(exact))
	for _, arn := range exact {
		if i, ok := index[arn]; ok {
			picked = append(picked, i)
		}
	}
	slices.Sort(picked)
	picked = slices.Compact(picked)
	out := make([]*graph.Node, len(picked))
	for k, i := range picked {
		out[k] = targets[i]
	}
	return out
}

// notServiceLinked skips service-linked roles, whose trust and permissions
// customers cannot edit (IAM documentation on service-linked roles).
func notServiceLinked(ctx *Context, _, target *graph.Node) ([]string, bool) {
	return nil, ctx.Env.Principal(target.ID) != nil && ctx.Env.Principal(target.ID).ServiceLinked
}

// canAssumeOnceTrusted checks that the actor could assume the role after
// the trust policy names it directly (same-account and cross-account rules
// still apply, including the actor's boundary and SCPs).
func canAssumeOnceTrusted(ctx *Context, actor, target *graph.Node, c *check) {
	if actor.Kind == graph.NodeGroup {
		c.ok = false // groups cannot be named in a trust policy
		return
	}
	trust := &eval.Policy{
		Type: eval.TypeResource, Source: "rewritten-trust:" + target.ARN, Name: "rewritten trust policy",
		Doc: &policy.Document{Version: policy.Version2012, Statements: []policy.Statement{{
			Effect: policy.Allow, Principal: &policy.Principal{AWS: policy.StringList{actor.ARN}},
			Action: policy.StringList{"sts:AssumeRole"},
		}}},
	}
	pr := ctx.Env.Principal(actor.ID)
	c.add(actor.ID, "sts:AssumeRole", ctx.Env.AskWithPolicy(pr, "sts:AssumeRole", target.ARN, target.Account, trust, nil))
}

// keyCountBelowTwo needs the access key count; unknown counts make the edge
// conditional and two keys rule it out (a user can hold at most two).
func keyCountBelowTwo(ctx *Context, _, target *graph.Node) ([]string, bool) {
	a := accountOf(ctx, target.Account)
	if a == nil || a.Extras == nil {
		return []string{"target user has fewer than 2 access keys (key count not collected)"}, false
	}
	return nil, a.Extras.AccessKeys[target.ARN] >= 2
}

// loginProfile returns a prerequisite check on whether the target user has
// a console password: want=false for CreateLoginProfile, true for Update.
func loginProfile(want bool) func(*Context, *graph.Node, *graph.Node) ([]string, bool) {
	return func(ctx *Context, _, target *graph.Node) ([]string, bool) {
		a := accountOf(ctx, target.Account)
		if a == nil || a.Extras == nil {
			if want {
				return []string{"target user has a console password (login profiles not collected)"}, false
			}
			return []string{"target user has no console password yet (login profiles not collected)"}, false
		}
		return nil, a.Extras.LoginProfiles[target.ARN] != want
	}
}

// notMember skips groups the user already belongs to.
func notMember(ctx *Context, actor, target *graph.Node) ([]string, bool) {
	return nil, ctx.Graph.Edge(graph.EdgeID(actor.ID, target.ID, graph.EdgeMemberOf)) != nil
}

func accountOf(ctx *Context, id string) *snapshot.Account {
	for _, a := range ctx.Snap.Accounts {
		if a.ID == id {
			return a
		}
	}
	return nil
}

func snapRole(ctx *Context, account, arn string) *snapshot.Role {
	if a := accountOf(ctx, account); a != nil {
		for _, r := range a.Roles {
			if r.ARN == arn {
				return r
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Family: pass a role to a new compute resource (new PassRole).

type passRoleRule struct {
	meta    Metadata
	service string // service principal that must be trusted, e.g. "lambda.amazonaws.com"
	// prereqs returns unverified prerequisites for the target role.
	prereqs func(ctx *Context, role *graph.Node) []string
}

func (r passRoleRule) Meta() Metadata { return r.meta }
func (r passRoleRule) Pass() Pass     { return PassPrimitive }

func (r passRoleRule) Apply(ctx *Context) []Finding {
	svcNode := ctx.Graph.Node(graph.NodeID("service:" + r.service))
	if svcNode == nil {
		return nil // no role trusts this service
	}
	var roles []*graph.Node
	for _, e := range ctx.Graph.Out(svcNode.ID) {
		if e.Kind == graph.EdgeTrust {
			roles = append(roles, ctx.Graph.Node(e.To))
		}
	}
	for _, actor := range actors(ctx, "iam:PassRole", iamActors...) {
		pr := ctx.Env.Principal(actor.ID)
		// The compute actions do not depend on the role: check them once.
		compute := newCheck()
		for _, a := range r.meta.RequiredActions {
			if a == "iam:PassRole" {
				continue
			}
			compute.add(actor.ID, a, ctx.Env.Ask(pr, a, "", actor.Account, "", nil))
			if !compute.ok {
				break
			}
		}
		if !compute.ok {
			continue
		}
		for _, role := range roles {
			if role.ID == actor.ID || role.Account != actor.Account {
				continue // PassRole only works in the caller's account (E33)
			}
			c := newCheck()
			passCtx := eval.WithPassedToService(eval.NewContext(pr, ctx.Env.OrgID), r.service)
			c.add(actor.ID, "iam:PassRole", ctx.Env.Ask(pr, "iam:PassRole", role.ARN, role.Account, "", passCtx))
			if !c.ok {
				continue
			}
			c.conditional = c.conditional || compute.conditional
			c.unevaluated = append(c.unevaluated, compute.unevaluated...)
			c.evidence = append(c.evidence, compute.evidence...)
			var prereqs []string
			if r.prereqs != nil {
				prereqs = r.prereqs(ctx, role)
			}
			ctx.Graph.AddEdge(edgeFor(r.meta, actor.ID, role.ID, c, prereqs))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Family: modify another principal and act as it (composite, PassComposite).

type compositeRule struct {
	meta Metadata
	// modify are the actions that rewrite the target's permissions; any one
	// of them is enough. requiredOn picks the resource it authorizes.
	modify     []string
	targetKind graph.NodeKind
	// actAs are the edge kinds that let the actor become the target.
	actAs []graph.EdgeKind
}

func (r compositeRule) Meta() Metadata { return r.meta }
func (r compositeRule) Pass() Pass     { return PassComposite }

// LatentLimit caps the latent edges kept per (rule, actor): an actor that
// can modify the permissions of every role would otherwise add one edge per
// role. The rule reports the cap in a finding instead.
const LatentLimit = 10

func (r compositeRule) Apply(ctx *Context) []Finding {
	var findings []Finding
	targets := nodesOfKind(ctx, r.targetKind)
	for _, actor := range ctx.Graph.Nodes() {
		if actor.Tier == 0 || !kindIn(actor.Kind, iamActors) {
			continue
		}
		pr := ctx.Env.Principal(actor.ID)
		possible := false
		for _, m := range r.modify {
			possible = possible || graph.MayAllow(pr, m)
		}
		if !possible {
			continue
		}
		// Composite edges need an act-as edge, so only the actor's
		// neighbors are candidates.
		reachable := map[string]bool{}
		for _, e := range ctx.Graph.Out(actor.ID) {
			if t := ctx.Graph.Node(e.To); t != nil && t.Kind == r.targetKind && r.usable(ctx, actor, t) {
				reachable[t.ID] = true
			}
		}
		ids := make([]string, 0, len(reachable))
		for id := range reachable {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			target := ctx.Graph.Node(id)
			via := r.actAsEdge(ctx, actor, target)
			if via == nil {
				continue
			}
			mod, action := r.firstModify(ctx, actor, target)
			if mod == nil {
				continue
			}
			mod.conditional = mod.conditional || via.Status != graph.StatusAllowed
			mod.unevaluated = append(mod.unevaluated, via.ConditionsUnevaluated...)
			mod.evidence = append(mod.evidence, via.Evidence...)
			e := edgeFor(r.meta, actor.ID, sinkOf(target.Account), mod, via.PrerequisitesUnverified)
			e.RequiredActions = append([]string{action}, via.RequiredActions...)
			e.Actor = actor.ID
			ctx.Graph.AddEdge(e)
		}
		// Latent edges: targets the actor can modify but not act as.
		kept := 0
		for _, target := range targets {
			if reachable[target.ID] && r.actAsEdge(ctx, actor, target) != nil || !r.usable(ctx, actor, target) {
				continue
			}
			mod, action := r.firstModify(ctx, actor, target)
			if mod == nil {
				continue
			}
			if kept == LatentLimit {
				findings = append(findings, Finding{
					RuleID: r.meta.ID, Severity: High, NodeID: actor.ID, Title: r.meta.Title,
					Message:  fmt.Sprintf("%s can modify the permissions of more than %d %ss with %s; only the first %d are kept as latent edges", actor.ARN, LatentLimit, r.targetKind, action, LatentLimit),
					Location: Location{Account: actor.Account, Entity: actor.ARN, Statement: -1},
				})
				break
			}
			kept++
			latent := edgeFor(r.meta, actor.ID, target.ID, mod, nil)
			latent.Kind, latent.Latent = graph.EdgeModifyPermissions, true
			latent.RequiredActions = []string{action}
			ctx.Graph.AddEdge(latent)
		}
	}
	return findings
}

func (r compositeRule) usable(ctx *Context, actor, target *graph.Node) bool {
	if target.ID == actor.ID || target.Tier == 0 {
		return false
	}
	tp := ctx.Env.Principal(target.ID)
	return tp == nil || !tp.ServiceLinked
}

// firstModify returns the first modify action the actor may perform on the
// target (for CreatePolicyVersion: on a customer policy attached to it).
func (r compositeRule) firstModify(ctx *Context, actor, target *graph.Node) (*check, string) {
	for _, action := range r.modify {
		resources := []string{target.ARN}
		if action == "iam:CreatePolicyVersion" {
			resources = attachedCustomerPolicies(ctx, target)
		}
		for _, res := range resources {
			c := askAll(ctx, actor, []string{action}, res, target.Account)
			if c.ok {
				return c, action
			}
		}
	}
	return nil, ""
}

func (r compositeRule) actAsEdge(ctx *Context, actor, target *graph.Node) *graph.Edge {
	for _, k := range r.actAs {
		if e := ctx.Graph.Edge(graph.EdgeID(actor.ID, target.ID, k)); e != nil && !e.Latent {
			return e
		}
	}
	return nil
}

// rolesTrusting returns the roles that trust a service principal.
func rolesTrusting(ctx *Context, service string) []*graph.Node {
	svc := ctx.Graph.Node(graph.NodeID("service:" + service))
	if svc == nil {
		return nil
	}
	var out []*graph.Node
	for _, e := range ctx.Graph.Out(svc.ID) {
		if e.Kind == graph.EdgeTrust {
			out = append(out, ctx.Graph.Node(e.To))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Family: change the code or commands of an existing resource that runs
// with a role (existing PassRole, update_code edges).

type updateCodeRule struct {
	meta    Metadata
	service string // service principal the role trusts
	// resources lists the resources running with the role. inventoried is
	// false when the snapshot has no inventory for this resource type.
	resources func(ctx *Context, role *graph.Node) (arns []string, inventoried bool)
	noun      string // e.g. "a Lambda function"
}

func (r updateCodeRule) Meta() Metadata { return r.meta }
func (r updateCodeRule) Pass() Pass     { return PassPrimitive }

func (r updateCodeRule) Apply(ctx *Context) []Finding {
	roles := rolesTrusting(ctx, r.service)
	for _, actor := range actors(ctx, r.meta.RequiredActions[0], iamActors...) {
		for _, role := range roles {
			if role.ID == actor.ID {
				continue
			}
			arns, inventoried := r.resources(ctx, role)
			var prereqs []string
			if !inventoried {
				arns = []string{""} // any resource: is the action possible at all?
				prereqs = []string{r.noun + " runs with this role (no resource inventory)"}
			}
			for _, res := range arns {
				c := askAll(ctx, actor, r.meta.RequiredActions, res, role.Account)
				if c.ok {
					ctx.Graph.AddEdge(edgeFor(r.meta, actor.ID, role.ID, c, prereqs))
					break
				}
			}
		}
	}
	return nil
}

func lambdaFunctions(ctx *Context, role *graph.Node) ([]string, bool) {
	a := accountOf(ctx, role.Account)
	if a == nil || a.Resources == nil {
		return nil, false
	}
	var out []string
	for _, f := range a.Resources.Lambda {
		if f.Role == role.ARN {
			out = append(out, f.ARN)
		}
	}
	return out, true
}

func ssmInstances(ctx *Context, role *graph.Node) ([]string, bool) {
	a := accountOf(ctx, role.Account)
	r := snapRole(ctx, role.Account, role.ARN)
	if a == nil || a.Resources == nil || r == nil {
		return nil, false
	}
	profiles := map[string]bool{}
	for _, p := range r.InstanceProfiles {
		profiles[p] = true
	}
	var out []string
	for _, i := range a.Resources.EC2 {
		if i.SSMManaged && profiles[i.InstanceProfile] {
			out = append(out, i.ARN)
		}
	}
	return out, true
}

func codeBuildProjects(ctx *Context, role *graph.Node) ([]string, bool) {
	a := accountOf(ctx, role.Account)
	if a == nil || a.Resources == nil {
		return nil, false
	}
	var out []string
	for _, p := range a.Resources.CodeBuild {
		if p.ServiceRole == role.ARN {
			out = append(out, p.ARN)
		}
	}
	return out, true
}

// inInstanceProfile is the EC2 prerequisite: the role must be in an
// instance profile (authorization details list them per role).
func inInstanceProfile(ctx *Context, role *graph.Node) []string {
	if r := snapRole(ctx, role.Account, role.ARN); r != nil && len(r.InstanceProfiles) > 0 {
		return nil
	}
	return []string{"the role is in an instance profile (it is not; iam:CreateInstanceProfile and iam:AddRoleToInstanceProfile would be needed)"}
}

// clusterExists is the ECS prerequisite: a cluster to run the task in.
func clusterExists(*Context, *graph.Node) []string {
	return []string{"an ECS cluster exists or can be created (not collected)"}
}
