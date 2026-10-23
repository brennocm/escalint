// Package graph is the "can act as" graph: X → Y means X can obtain Y's
// privileges (or more). docs/research.md §6 and ADR 0006 define the node and
// edge kinds; rules add escalation edges, this package adds the structural
// ones and keeps everything deterministic.
package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// NodeKind is the type of a node.
type NodeKind string

// Node kinds (contract: nodes[].kind).
const (
	NodeUser            NodeKind = "user"
	NodeRole            NodeKind = "role"
	NodeGroup           NodeKind = "group"
	NodeService         NodeKind = "service"
	NodeExternalAccount NodeKind = "external_account"
	NodeFederated       NodeKind = "federated"
	NodeAnyPrincipal    NodeKind = "any_principal"
	NodeTier0Sink       NodeKind = "tier0_sink"
)

// EdgeKind is the type of an edge.
type EdgeKind string

// Edge kinds (contract: edges[].kind).
const (
	EdgeAssume            EdgeKind = "assume"
	EdgeTrust             EdgeKind = "trust"
	EdgeCredential        EdgeKind = "credential"
	EdgeModifyPermissions EdgeKind = "modify_permissions"
	EdgeModifyTrust       EdgeKind = "modify_trust"
	EdgePassRoleCompute   EdgeKind = "passrole_compute"
	EdgeUpdateCode        EdgeKind = "update_code"
	EdgeMemberOf          EdgeKind = "member_of"
	EdgeAdmin             EdgeKind = "admin"
)

// Escalates reports whether the edge kind is an escalation step (structural
// member_of edges are not).
func (k EdgeKind) Escalates() bool {
	return k != EdgeMemberOf
}

// Status of an edge.
type Status string

// Edge statuses.
const (
	StatusAllowed     Status = "allowed"
	StatusConditional Status = "conditional"
)

// Node is a principal, a principal type outside the snapshot, or a sink.
type Node struct {
	ID       string
	Kind     NodeKind
	Key      string // canonical identity: ARN, "service:<name>", "account:<id>"…
	ARN      string
	Name     string
	Account  string
	Path     string
	Tags     map[string]string
	LastUsed *time.Time
	Flags    []string // sorted: "stale", "external_trust", "no_boundary", "service_linked"

	// Set by analyses.
	Tier            int
	TierConditional bool
}

// Evidence is one policy statement that justifies an edge.
type Evidence struct {
	Principal string // node ID whose policy granted the action
	Action    string
	Policy    string // policy source (ARN, inline:…, trust:…)
	Statement int
	Sid       string
	Effect    string
	Stage     string // identity, boundary, resource, scp, rcp
}

// Edge is a "can act as" relation.
type Edge struct {
	ID                      string
	From, To                string
	Kind                    EdgeKind
	RuleIDs                 []string
	PathfindingIDs          []string
	Status                  Status
	RequiredActions         []string
	Evidence                []Evidence
	ConditionsUnevaluated   []string
	PrerequisitesUnverified []string
	// Latent edges (modify_permissions on another principal without a way to
	// act as it) are reported but never used by path search.
	Latent bool
	// Actor is set on composite edges: the principal that performs the
	// modification (it differs from From only for structural composites).
	Actor string
}

// hashID returns prefix + the first 16 hex digits of SHA-256(key).
func hashID(prefix, key string) string {
	sum := sha256.Sum256([]byte(key))
	return prefix + hex.EncodeToString(sum[:])[:16]
}

// NodeID is the stable ID of a node with the given canonical key.
func NodeID(key string) string { return hashID("n_", key) }

// EdgeID is the stable ID of an edge.
func EdgeID(from, to string, kind EdgeKind) string {
	return hashID("e_", from+"|"+to+"|"+string(kind))
}

// PathID is the stable ID of a path given its edge IDs.
func PathID(edges []string) string { return hashID("p_", strings.Join(edges, ",")) }

// Graph holds nodes and edges with deterministic iteration order. It is not
// safe for concurrent use: reads sort adjacency lists lazily.
type Graph struct {
	nodes map[string]*Node
	edges map[string]*Edge
	out   map[string][]*Edge // sorted by (To, ID) once read
	in    map[string][]*Edge
	// Adjacency lists changed since they were last sorted.
	dirtyOut, dirtyIn map[string]bool
	// Sorted views, rebuilt after inserts.
	sortedNodes []*Node
	sortedEdges []*Edge
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{
		nodes: map[string]*Node{}, edges: map[string]*Edge{}, out: map[string][]*Edge{}, in: map[string][]*Edge{},
		dirtyOut: map[string]bool{}, dirtyIn: map[string]bool{},
	}
}

// AddNode inserts n (its ID is derived from Key) or returns the existing
// node with the same key.
func (g *Graph) AddNode(n *Node) *Node {
	n.ID = NodeID(n.Key)
	if existing, ok := g.nodes[n.ID]; ok {
		return existing
	}
	g.nodes[n.ID] = n
	g.sortedNodes = nil
	return n
}

// Node returns the node with the given ID, or nil.
func (g *Graph) Node(id string) *Node { return g.nodes[id] }

// Edge returns the edge with the given ID, or nil.
func (g *Graph) Edge(id string) *Edge { return g.edges[id] }

// AddEdge inserts e or merges it into the existing edge with the same
// endpoints and kind: rule IDs, actions, evidence and unevaluated keys are
// unioned; the status becomes allowed if either is allowed; latent only if
// both are latent.
func (g *Graph) AddEdge(e *Edge) *Edge {
	e.ID = EdgeID(e.From, e.To, e.Kind)
	if cur, ok := g.edges[e.ID]; ok {
		cur.RuleIDs = union(cur.RuleIDs, e.RuleIDs)
		cur.PathfindingIDs = union(cur.PathfindingIDs, e.PathfindingIDs)
		cur.RequiredActions = union(cur.RequiredActions, e.RequiredActions)
		cur.Evidence = mergeEvidence(cur.Evidence, e.Evidence)
		if cur.Status == StatusAllowed || e.Status == StatusAllowed {
			// The edge exists unconditionally through one variant; the
			// conditions of the other variant no longer gate it.
			if e.Status == StatusAllowed && cur.Status != StatusAllowed {
				cur.ConditionsUnevaluated = e.ConditionsUnevaluated
				cur.PrerequisitesUnverified = e.PrerequisitesUnverified
			}
			cur.Status = StatusAllowed
		} else {
			cur.ConditionsUnevaluated = union(cur.ConditionsUnevaluated, e.ConditionsUnevaluated)
			cur.PrerequisitesUnverified = union(cur.PrerequisitesUnverified, e.PrerequisitesUnverified)
		}
		cur.Latent = cur.Latent && e.Latent
		return cur
	}
	e.RuleIDs = union(nil, e.RuleIDs)
	e.PathfindingIDs = union(nil, e.PathfindingIDs)
	e.RequiredActions = union(nil, e.RequiredActions)
	e.ConditionsUnevaluated = union(nil, e.ConditionsUnevaluated)
	e.PrerequisitesUnverified = union(nil, e.PrerequisitesUnverified)
	e.Evidence = mergeEvidence(nil, e.Evidence)
	g.edges[e.ID] = e
	g.out[e.From] = append(g.out[e.From], e)
	g.in[e.To] = append(g.in[e.To], e)
	g.dirtyOut[e.From], g.dirtyIn[e.To] = true, true
	g.sortedEdges = nil
	return e
}

// RemoveEdges returns a copy of the graph without the given edges (nodes are
// shared). Used by the fix plan to check that a change cuts paths.
func (g *Graph) RemoveEdges(ids map[string]bool) *Graph {
	c := New()
	for id, n := range g.nodes {
		c.nodes[id] = n
	}
	for _, e := range g.Edges() {
		if ids[e.ID] {
			continue
		}
		c.edges[e.ID] = e
		c.out[e.From] = append(c.out[e.From], e)
		c.in[e.To] = append(c.in[e.To], e)
	}
	// Edges() is sorted by ID, not by endpoint: re-sort every list.
	for id := range c.out {
		c.dirtyOut[id] = true
	}
	for id := range c.in {
		c.dirtyIn[id] = true
	}
	return c
}

// sortList orders an adjacency list by the far endpoint, then edge ID.
func sortList(list []*Edge, byTo bool) {
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		ka, kb := a.To, b.To
		if !byTo {
			ka, kb = a.From, b.From
		}
		if ka != kb {
			return ka < kb
		}
		return a.ID < b.ID
	})
}

// Out returns the edges leaving id, sorted by target then edge ID.
func (g *Graph) Out(id string) []*Edge {
	if g.dirtyOut[id] {
		sortList(g.out[id], true)
		delete(g.dirtyOut, id)
	}
	return g.out[id]
}

// In returns the edges entering id, sorted by source then edge ID.
func (g *Graph) In(id string) []*Edge {
	if g.dirtyIn[id] {
		sortList(g.in[id], false)
		delete(g.dirtyIn, id)
	}
	return g.in[id]
}

// Nodes returns every node sorted by ID. The slice is shared: callers must
// not modify it.
func (g *Graph) Nodes() []*Node {
	if g.sortedNodes == nil {
		g.sortedNodes = make([]*Node, 0, len(g.nodes))
		for _, n := range g.nodes {
			g.sortedNodes = append(g.sortedNodes, n)
		}
		sort.Slice(g.sortedNodes, func(i, j int) bool { return g.sortedNodes[i].ID < g.sortedNodes[j].ID })
	}
	return g.sortedNodes
}

// Edges returns every edge sorted by ID. The slice is shared: callers must
// not modify it. Adding edges while iterating is safe: the iteration keeps
// the old view.
func (g *Graph) Edges() []*Edge {
	if g.sortedEdges == nil {
		g.sortedEdges = make([]*Edge, 0, len(g.edges))
		for _, e := range g.edges {
			g.sortedEdges = append(g.sortedEdges, e)
		}
		sort.Slice(g.sortedEdges, func(i, j int) bool { return g.sortedEdges[i].ID < g.sortedEdges[j].ID })
	}
	return g.sortedEdges
}

// Sinks returns the tier0 sink nodes sorted by ID.
func (g *Graph) Sinks() []*Node {
	var out []*Node
	for _, n := range g.Nodes() {
		if n.Kind == NodeTier0Sink {
			out = append(out, n)
		}
	}
	return out
}

func union(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func mergeEvidence(a, b []Evidence) []Evidence {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	seen := map[Evidence]bool{}
	var out []Evidence
	for _, list := range [][]Evidence{a, b} {
		for _, ev := range list {
			if !seen[ev] {
				seen[ev] = true
				out = append(out, ev)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		x, y := out[i], out[j]
		switch {
		case x.Principal != y.Principal:
			return x.Principal < y.Principal
		case x.Action != y.Action:
			return x.Action < y.Action
		case x.Policy != y.Policy:
			return x.Policy < y.Policy
		case x.Statement != y.Statement:
			return x.Statement < y.Statement
		default:
			return x.Stage < y.Stage
		}
	})
	return out
}
