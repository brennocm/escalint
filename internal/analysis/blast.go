package analysis

import (
	"sort"

	"github.com/brennocm/escalint/internal/catalog"
	"github.com/brennocm/escalint/internal/eval"
	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/match"
)

// Class is a capability class of blast radius (ADR 0008).
type Class string

// Capability classes, strongest first.
const (
	ClassPermissionManagement Class = "permission_management"
	ClassWrite                Class = "write"
	ClassRead                 Class = "read"
	ClassList                 Class = "list"
)

var classOrder = []Class{ClassPermissionManagement, ClassWrite, ClassRead, ClassList}

func classOf(l catalog.AccessLevel) Class {
	switch l {
	case catalog.PermissionManagement:
		return ClassPermissionManagement
	case catalog.Write, catalog.Tagging:
		return ClassWrite
	case catalog.List:
		return ClassList
	case catalog.Read:
		return ClassRead
	}
	return ClassRead
}

// Capabilities maps a service prefix to the strongest class the principal
// can use on some resource.
type Capabilities map[string]Class

// CapabilityFinder computes capabilities with the evaluator in "any
// resource" mode, caching results for principals that share exactly the
// same policies and have no principal-specific conditions.
type CapabilityFinder struct {
	Catalog *catalog.Catalog
	Env     *graph.Env
	cache   map[string]Capabilities
}

// NewCapabilityFinder returns a finder bound to a graph environment.
func NewCapabilityFinder(c *catalog.Catalog, env *graph.Env) *CapabilityFinder {
	return &CapabilityFinder{Catalog: c, Env: env, cache: map[string]Capabilities{}}
}

// For returns the capabilities of a user, role or group node (nil for
// other nodes).
func (f *CapabilityFinder) For(nodeID string) Capabilities {
	pr := f.Env.Principal(nodeID)
	if pr == nil {
		return nil
	}
	key := cacheKey(pr)
	if caps, ok := f.cache[key]; ok {
		return caps
	}
	caps := f.compute(pr)
	f.cache[key] = caps
	return caps
}

// candidates are the catalog actions some Allow statement may match, grouped
// by service and class.
func (f *CapabilityFinder) candidates(pr *eval.Principal) map[string]map[Class][]catalog.Action {
	out := map[string]map[Class][]catalog.Action{}
	addAll := func(actions []catalog.Action) {
		for _, a := range actions {
			if out[a.Service] == nil {
				out[a.Service] = map[Class][]catalog.Action{}
			}
			c := classOf(a.Access)
			out[a.Service][c] = append(out[a.Service][c], a)
		}
	}
	for _, p := range pr.Identity {
		if p.Doc == nil {
			continue
		}
		for i := range p.Doc.Statements {
			st := &p.Doc.Statements[i]
			if st.Effect != "Allow" {
				continue
			}
			patterns, negated := st.ActionPatterns()
			if negated {
				// Everything except the listed actions.
				for _, svc := range f.Catalog.Services() {
					var keep []catalog.Action
					for _, a := range svc.Actions {
						if !anyMatch(patterns, a.String()) {
							keep = append(keep, a)
						}
					}
					addAll(keep)
				}
				continue
			}
			for _, pat := range patterns {
				addAll(f.Catalog.Expand(pat))
			}
		}
	}
	return out
}

func anyMatch(patterns []string, action string) bool {
	for _, p := range patterns {
		if match.Action(p, action) {
			return true
		}
	}
	return false
}

func (f *CapabilityFinder) compute(pr *eval.Principal) Capabilities {
	caps := Capabilities{}
	byService := f.candidates(pr)
	services := make([]string, 0, len(byService))
	for s := range byService {
		services = append(services, s)
	}
	sort.Strings(services)
	ctx := eval.NewContext(pr, f.Env.OrgID)
	for _, svc := range services {
	classes:
		for _, c := range classOrder {
			seen := map[string]bool{}
			for _, a := range byService[svc][c] {
				if seen[a.Name] {
					continue
				}
				seen[a.Name] = true
				res := f.Env.Ask(pr, a.String(), "", "", "", ctx)
				if res.Decision.Allowed() {
					caps[svc] = c
					break classes
				}
			}
		}
	}
	return caps
}

// cacheKey identifies principals with identical policies. Principals whose
// policies use conditions or variables are evaluated individually, because
// aws:PrincipalArn or ${aws:username} make the answer depend on who they are.
func cacheKey(pr *eval.Principal) string {
	key := pr.Account + "|" + string(pr.Kind)
	personal := false
	add := func(p *eval.Policy) {
		key += "|" + p.Source
		if p.Doc == nil {
			return
		}
		for _, st := range p.Doc.Statements {
			if len(st.Condition) > 0 {
				personal = true
			}
			for _, r := range append(append([]string(nil), st.Resource...), st.NotResource...) {
				if containsVariable(r) {
					personal = true
				}
			}
		}
	}
	for i := range pr.Identity {
		add(&pr.Identity[i])
	}
	if pr.Boundary != nil {
		key += "|boundary"
		add(pr.Boundary)
	}
	if pr.SCPs != nil {
		key += "|scps"
	}
	if pr.ServiceLinked {
		key += "|slr"
	}
	if personal {
		key += "|" + pr.ARN
	}
	return key
}

func containsVariable(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '$' && s[i+1] == '{' {
			return true
		}
	}
	return false
}

// Blast is the blast radius vector of a node (never a single number).
type Blast struct {
	ReachablePrincipals int
	ReachesTier0        bool
	Capabilities        map[Class][]string // services per strongest class, sorted
}

// BlastRadius combines a node's own capabilities with those of every
// principal it can reach within maxDepth.
func BlastRadius(g *graph.Graph, finder *CapabilityFinder, nodeID string, maxDepth int) Blast {
	reach := Reach(g, nodeID, Out, maxDepth)
	b := Blast{Capabilities: map[Class][]string{}}
	best := Capabilities{}
	merge := func(c Capabilities) {
		for svc, cls := range c {
			if cur, ok := best[svc]; !ok || rank(cls) < rank(cur) {
				best[svc] = cls
			}
		}
	}
	if n := g.Node(nodeID); n != nil && n.Tier == 0 {
		b.ReachesTier0 = true
	}
	merge(finder.For(nodeID))
	ids := make([]string, 0, len(reach))
	for id := range reach {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := g.Node(id)
		switch n.Kind {
		case graph.NodeTier0Sink:
			b.ReachesTier0 = true
		case graph.NodeUser, graph.NodeRole, graph.NodeGroup:
			b.ReachablePrincipals++
			merge(finder.For(id))
		case graph.NodeService, graph.NodeExternalAccount, graph.NodeFederated, graph.NodeAnyPrincipal:
		}
	}
	for svc, cls := range best {
		b.Capabilities[cls] = append(b.Capabilities[cls], svc)
	}
	for _, list := range b.Capabilities {
		sort.Strings(list)
	}
	return b
}

func rank(c Class) int {
	for i, x := range classOrder {
		if x == c {
			return i
		}
	}
	return len(classOrder)
}
