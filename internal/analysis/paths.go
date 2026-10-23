package analysis

import (
	"sort"
	"strings"

	"github.com/brennocm/escalint/internal/graph"
)

// DefaultK is the number of shortest paths kept per source.
const DefaultK = 3

// Path is a simple path from a principal to a tier0 sink.
type Path struct {
	ID     string
	Source string
	Target string   // sink node ID
	Edges  []string // edge IDs in order
	Nodes  []string // node IDs, Source first, Target last
	Status graph.Status
}

// Length is the number of edges.
func (p Path) Length() int { return len(p.Edges) }

// PathOptions bounds the enumeration.
type PathOptions struct {
	K        int // paths per source (default DefaultK)
	MaxDepth int // maximum edges per path (default DefaultMaxDepth)
}

func (o PathOptions) withDefaults() PathOptions {
	if o.K <= 0 {
		o.K = DefaultK
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = DefaultMaxDepth
	}
	return o
}

// IsSource reports whether paths start at this node: principals that could
// act (users, roles, external accounts, federated providers, anyone) and are
// not already Tier 0. Groups are only reached by joining them; services are
// not attackers.
func IsSource(n *graph.Node) bool {
	switch n.Kind {
	case graph.NodeUser, graph.NodeRole:
		return n.Tier != 0
	case graph.NodeExternalAccount, graph.NodeFederated, graph.NodeAnyPrincipal:
		return true
	case graph.NodeGroup, graph.NodeService, graph.NodeTier0Sink:
		return false
	}
	return false
}

// Enumerate returns up to K shortest simple paths from every source to a
// tier0 sink (Yen's algorithm on hop counts, ADR 0007), sorted by source,
// length and ID.
func Enumerate(g *graph.Graph, opts PathOptions) []Path {
	opts = opts.withDefaults()
	toSink := distanceToSinks(g, opts.MaxDepth)
	var all []Path
	for _, n := range g.Nodes() {
		if !IsSource(n) {
			continue
		}
		if _, ok := toSink[n.ID]; !ok {
			continue // cannot reach any sink within the depth limit
		}
		all = append(all, kShortest(g, n.ID, opts, toSink)...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		switch {
		case a.Source != b.Source:
			return a.Source < b.Source
		case len(a.Edges) != len(b.Edges):
			return len(a.Edges) < len(b.Edges)
		default:
			return a.ID < b.ID
		}
	})
	return all
}

// kShortest is Yen's algorithm from src to any sink.
func kShortest(g *graph.Graph, src string, opts PathOptions, toSink map[string]int) []Path {
	first := shortest(g, src, nil, nil, opts.MaxDepth, toSink)
	if first == nil {
		return nil
	}
	accepted := [][]*graph.Edge{first}
	var candidates [][]*graph.Edge
	seen := map[string]bool{pathKey(first): true}

	for len(accepted) < opts.K {
		prev := accepted[len(accepted)-1]
		for i := range prev {
			root := prev[:i]
			spurNode := src
			if i > 0 {
				spurNode = prev[i-1].To
			}
			removedEdges := map[string]bool{}
			for _, p := range accepted {
				if len(p) > i && sameEdges(p[:i], root) {
					removedEdges[p[i].ID] = true
				}
			}
			removedNodes := map[string]bool{src: spurNode != src}
			for _, e := range root {
				if e.To != spurNode {
					removedNodes[e.To] = true
				}
			}
			spur := shortest(g, spurNode, removedEdges, removedNodes, opts.MaxDepth-i, toSink)
			if spur == nil {
				continue
			}
			total := append(append([]*graph.Edge(nil), root...), spur...)
			if k := pathKey(total); !seen[k] {
				seen[k] = true
				candidates = append(candidates, total)
			}
		}
		if len(candidates) == 0 {
			break
		}
		sort.SliceStable(candidates, func(i, j int) bool {
			if len(candidates[i]) != len(candidates[j]) {
				return len(candidates[i]) < len(candidates[j])
			}
			return pathKey(candidates[i]) < pathKey(candidates[j])
		})
		accepted = append(accepted, candidates[0])
		candidates = candidates[1:]
	}

	out := make([]Path, 0, len(accepted))
	for _, edges := range accepted {
		out = append(out, toPath(src, edges))
	}
	return out
}

// shortest is a breadth-first search from src to the nearest sink, visiting
// neighbors in (target, edge ID) order so the result is deterministic. It
// skips removed edges and nodes and prunes nodes that cannot reach a sink
// within the remaining budget.
func shortest(g *graph.Graph, src string, removedEdges, removedNodes map[string]bool, budget int, toSink map[string]int) []*graph.Edge {
	if budget <= 0 {
		return nil
	}
	if d, ok := toSink[src]; !ok || d > budget {
		return nil
	}
	parent := map[string]*graph.Edge{}
	visited := map[string]bool{src: true}
	frontier := []string{src}
	for depth := 1; depth <= budget && len(frontier) > 0; depth++ {
		var next []string
		for _, id := range frontier {
			for _, e := range g.Out(id) {
				if !usable(e) || removedEdges[e.ID] || removedNodes[e.To] || visited[e.To] {
					continue
				}
				d, ok := toSink[e.To]
				if !ok || depth+d > budget {
					continue
				}
				visited[e.To] = true
				parent[e.To] = e
				if d == 0 { // reached a sink
					return unwind(parent, src, e.To)
				}
				next = append(next, e.To)
			}
		}
		frontier = next
	}
	return nil
}

func unwind(parent map[string]*graph.Edge, src, dst string) []*graph.Edge {
	var rev []*graph.Edge
	for cur := dst; cur != src; cur = parent[cur].From {
		rev = append(rev, parent[cur])
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

func toPath(src string, edges []*graph.Edge) Path {
	p := Path{Source: src, Nodes: []string{src}, Status: graph.StatusAllowed}
	for _, e := range edges {
		p.Edges = append(p.Edges, e.ID)
		p.Nodes = append(p.Nodes, e.To)
		if e.Status != graph.StatusAllowed {
			p.Status = graph.StatusConditional
		}
	}
	p.Target = p.Nodes[len(p.Nodes)-1]
	p.ID = graph.PathID(p.Edges)
	return p
}

func pathKey(edges []*graph.Edge) string {
	ids := make([]string, len(edges))
	for i, e := range edges {
		ids[i] = e.ID
	}
	return strings.Join(ids, ",")
}

func sameEdges(a, b []*graph.Edge) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			return false
		}
	}
	return true
}
