package analysis

import (
	"fmt"
	"math/rand"

	"github.com/brennocm/escalint/internal/graph"
)

// tg builds small graphs by node name for tests.
type tg struct {
	g     *graph.Graph
	nodes map[string]*graph.Node
}

func newTG() *tg { return &tg{g: graph.New(), nodes: map[string]*graph.Node{}} }

func (t *tg) node(name string, kind graph.NodeKind) *graph.Node {
	if n, ok := t.nodes[name]; ok {
		return n
	}
	n := t.g.AddNode(&graph.Node{Kind: kind, Key: name, Name: name, Tier: 3})
	t.nodes[name] = n
	return n
}

func (t *tg) role(name string) *graph.Node { return t.node(name, graph.NodeRole) }

func (t *tg) sink(name string) *graph.Node {
	n := t.node(name, graph.NodeTier0Sink)
	n.Tier = 0
	return n
}

func (t *tg) edge(from, to string, kind graph.EdgeKind) *graph.Edge {
	return t.g.AddEdge(&graph.Edge{From: t.nodes[from].ID, To: t.nodes[to].ID, Kind: kind, Status: graph.StatusAllowed})
}

func (t *tg) id(name string) string { return t.nodes[name].ID }

// randomGraph builds a seeded random graph with n roles, about avgOut edges
// per node and a few admins wired to one sink.
func randomGraph(seed int64, n int, avgOut float64) *graph.Graph {
	rng := rand.New(rand.NewSource(seed))
	t := newTG()
	t.sink("sink")
	for i := 0; i < n; i++ {
		t.role(fmt.Sprintf("r%05d", i))
	}
	kinds := []graph.EdgeKind{graph.EdgeAssume, graph.EdgePassRoleCompute, graph.EdgeModifyTrust, graph.EdgeCredential}
	for i := 0; i < n; i++ {
		from := fmt.Sprintf("r%05d", i)
		for k := 0; k < int(avgOut*2*rng.Float64()+0.5); k++ {
			to := fmt.Sprintf("r%05d", rng.Intn(n))
			if to != from {
				e := t.edge(from, to, kinds[rng.Intn(len(kinds))])
				if rng.Intn(5) == 0 {
					e.Status = graph.StatusConditional
				}
			}
		}
		if rng.Intn(50) == 0 {
			t.nodes[from].Tier = 0
			t.edge(from, "sink", graph.EdgeAdmin)
		}
	}
	return t.g
}
