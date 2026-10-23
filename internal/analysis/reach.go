// Package analysis runs graph algorithms over the can-act-as graph: reach,
// k shortest paths, cycles, tiers, blast radius, choke points and the fix
// plan. Every function is deterministic: neighbors are visited in ID order
// and ties are broken by ID.
package analysis

import "github.com/brennocm/escalint/internal/graph"

// DefaultMaxDepth bounds reach and path searches (hops).
const DefaultMaxDepth = 6

// Direction of a reach search.
type Direction int

// Directions.
const (
	Out Direction = iota // where can this node get to
	In                   // who can get to this node
)

// usable reports whether an edge may be part of an escalation: structural
// member_of edges and latent edges are not.
func usable(e *graph.Edge) bool {
	return e.Kind.Escalates() && !e.Latent
}

// Reach returns the hop distance from start to every node reachable within
// maxDepth (start excluded), following usable edges in the given direction.
func Reach(g *graph.Graph, start string, dir Direction, maxDepth int) map[string]int {
	dist := map[string]int{start: 0}
	frontier := []string{start}
	for depth := 1; depth <= maxDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, id := range frontier {
			edges := g.Out(id)
			if dir == In {
				edges = g.In(id)
			}
			for _, e := range edges {
				if !usable(e) {
					continue
				}
				other := e.To
				if dir == In {
					other = e.From
				}
				if _, seen := dist[other]; !seen {
					dist[other] = depth
					next = append(next, other)
				}
			}
		}
		frontier = next
	}
	delete(dist, start)
	return dist
}

// distanceToSinks returns, for every node that can reach a tier0 sink within
// maxDepth, the minimum number of hops to one. It is one reverse BFS from all
// sinks and lets path search prune branches that cannot finish in time.
func distanceToSinks(g *graph.Graph, maxDepth int) map[string]int {
	dist := map[string]int{}
	var frontier []string
	for _, s := range g.Sinks() {
		dist[s.ID] = 0
		frontier = append(frontier, s.ID)
	}
	for depth := 1; depth <= maxDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, id := range frontier {
			for _, e := range g.In(id) {
				if !usable(e) {
					continue
				}
				if _, seen := dist[e.From]; !seen {
					dist[e.From] = depth
					next = append(next, e.From)
				}
			}
		}
		frontier = next
	}
	return dist
}
