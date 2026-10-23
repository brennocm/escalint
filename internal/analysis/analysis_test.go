package analysis

import (
	"reflect"
	"testing"

	"pgregory.net/rapid"

	"github.com/brennocm/escalint/internal/graph"
)

// line: a -> b -> c(admin) -> sink
func lineGraph() *tg {
	t := newTG()
	t.sink("sink")
	t.role("a")
	t.role("b")
	t.role("c").Tier = 0
	t.edge("a", "b", graph.EdgeAssume)
	t.edge("b", "c", graph.EdgePassRoleCompute)
	t.edge("c", "sink", graph.EdgeAdmin)
	return t
}

// diamond: s -> {x, y} -> t(admin) -> sink, plus a direct long way s -> z -> w -> t.
func diamondGraph() *tg {
	t := newTG()
	t.sink("sink")
	for _, n := range []string{"s", "x", "y", "z", "w"} {
		t.role(n)
	}
	t.role("t").Tier = 0
	t.edge("s", "x", graph.EdgeAssume)
	t.edge("s", "y", graph.EdgeAssume)
	t.edge("x", "t", graph.EdgeAssume)
	t.edge("y", "t", graph.EdgeAssume)
	t.edge("s", "z", graph.EdgeAssume)
	t.edge("z", "w", graph.EdgeAssume)
	t.edge("w", "t", graph.EdgeAssume)
	t.edge("t", "sink", graph.EdgeAdmin)
	return t
}

func TestReach(t *testing.T) {
	tg := lineGraph()
	got := Reach(tg.g, tg.id("a"), Out, DefaultMaxDepth)
	want := map[string]int{tg.id("b"): 1, tg.id("c"): 2, tg.id("sink"): 3}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Reach(a, out) = %v, want %v", got, want)
	}
	if got := Reach(tg.g, tg.id("a"), Out, 1); len(got) != 1 {
		t.Errorf("depth limit ignored: %v", got)
	}
	in := Reach(tg.g, tg.id("sink"), In, DefaultMaxDepth)
	if in[tg.id("a")] != 3 || in[tg.id("c")] != 1 {
		t.Errorf("Reach(sink, in) = %v", in)
	}
}

func TestReachSkipsStructuralAndLatentEdges(t *testing.T) {
	tg := newTG()
	tg.node("u", graph.NodeUser)
	tg.node("grp", graph.NodeGroup)
	tg.role("r")
	tg.edge("u", "grp", graph.EdgeMemberOf)
	tg.edge("u", "r", graph.EdgeModifyPermissions).Latent = true
	if got := Reach(tg.g, tg.id("u"), Out, 6); len(got) != 0 {
		t.Errorf("Reach = %v, want nothing", got)
	}
}

func TestEnumerateLine(t *testing.T) {
	tg := lineGraph()
	paths := Enumerate(tg.g, PathOptions{})
	if len(paths) != 2 {
		t.Fatalf("paths = %+v, want one from a and one from b", paths)
	}
	a := paths[0]
	if a.Source != tg.id("a") && paths[1].Source == tg.id("a") {
		a = paths[1]
	}
	if a.Length() != 3 || a.Target != tg.id("sink") || a.Status != graph.StatusAllowed {
		t.Errorf("path from a = %+v", a)
	}
	if got := Enumerate(tg.g, PathOptions{MaxDepth: 2}); len(got) != 1 {
		t.Errorf("depth 2 must only keep b's path, got %d", len(got))
	}
}

func TestEnumerateDiamondKShortest(t *testing.T) {
	tg := diamondGraph()
	var fromS []Path
	for _, p := range Enumerate(tg.g, PathOptions{K: 5}) {
		if p.Source == tg.id("s") {
			fromS = append(fromS, p)
		}
	}
	if len(fromS) != 3 {
		t.Fatalf("paths from s = %d, want 3 (two of length 3, one of length 4)", len(fromS))
	}
	if fromS[0].Length() != 3 || fromS[1].Length() != 3 || fromS[2].Length() != 4 {
		t.Errorf("lengths = %d %d %d", fromS[0].Length(), fromS[1].Length(), fromS[2].Length())
	}
	if k1 := Enumerate(tg.g, PathOptions{K: 1}); countFrom(k1, tg.id("s")) != 1 {
		t.Error("K=1 must keep one path per source")
	}
}

func TestEnumerateCycleAndDisconnected(t *testing.T) {
	tg := newTG()
	tg.sink("sink")
	for _, n := range []string{"a", "b", "c", "island"} {
		tg.role(n)
	}
	tg.role("admin").Tier = 0
	tg.edge("a", "b", graph.EdgeAssume)
	tg.edge("b", "a", graph.EdgeAssume)
	tg.edge("b", "c", graph.EdgeAssume)
	tg.edge("c", "admin", graph.EdgeAssume)
	tg.edge("admin", "sink", graph.EdgeAdmin)
	paths := Enumerate(tg.g, PathOptions{K: 10})
	for _, p := range paths {
		assertSimple(t, p)
		if p.Source == tg.id("island") {
			t.Error("disconnected node has a path")
		}
	}
	if countFrom(paths, tg.id("a")) != 1 {
		t.Errorf("a has %d paths, want 1 (the cycle adds no simple path)", countFrom(paths, tg.id("a")))
	}
	cycles := Cycles(tg.g)
	if len(cycles) != 1 || len(cycles[0]) != 2 {
		t.Errorf("Cycles = %v, want [a b]", cycles)
	}
}

func TestEnumerateConditionalStatusAndSources(t *testing.T) {
	tg := newTG()
	tg.sink("sink")
	tg.node("ext", graph.NodeExternalAccount)
	tg.node("svc", graph.NodeService)
	tg.node("grp", graph.NodeGroup)
	tg.role("admin").Tier = 0
	tg.edge("ext", "admin", graph.EdgeTrust).Status = graph.StatusConditional
	tg.edge("svc", "admin", graph.EdgeTrust)
	tg.edge("grp", "admin", graph.EdgeAssume)
	tg.edge("admin", "sink", graph.EdgeAdmin)
	paths := Enumerate(tg.g, PathOptions{})
	if len(paths) != 1 || paths[0].Source != tg.id("ext") || paths[0].Status != graph.StatusConditional {
		t.Fatalf("paths = %+v, want one conditional path from the external account", paths)
	}
}

func TestCyclesStar(t *testing.T) {
	tg := newTG()
	for _, n := range []string{"hub", "a", "b", "c"} {
		tg.role(n)
	}
	for _, n := range []string{"a", "b", "c"} {
		tg.edge("hub", n, graph.EdgeAssume)
		tg.edge(n, "hub", graph.EdgeAssume)
	}
	if c := Cycles(tg.g); len(c) != 1 || len(c[0]) != 4 {
		t.Errorf("Cycles(star) = %v", c)
	}
}

func TestChokePointsAndFixPlan(t *testing.T) {
	tg := diamondGraph()
	paths := Enumerate(tg.g, PathOptions{K: 5})
	cps := ChokePoints(paths)
	admin := graph.EdgeID(tg.id("t"), tg.id("sink"), graph.EdgeAdmin)
	if cps[0].EdgeID != admin || cps[0].PathsCut != len(paths) || cps[0].Share != 1 {
		t.Errorf("top choke point = %+v, want the admin edge on every path", cps[0])
	}
	// Admin edges are not fixable by a policy change: the plan must pick the
	// next best edges instead.
	fixable := func(id string) bool { return tg.g.Edge(id).Kind != graph.EdgeAdmin }
	plan := FixPlan(paths, fixable)
	cut := map[string]bool{}
	for _, step := range plan {
		if !fixable(step.EdgeID) {
			t.Errorf("plan picked an unfixable edge %s", step.EdgeID)
		}
		cut[step.EdgeID] = true
	}
	assertPlanCutsAll(t, paths, plan)
	if len(FixPlan(nil, nil)) != 0 {
		t.Error("empty plan expected")
	}
}

func assertSimple(t *testing.T, p Path) {
	t.Helper()
	seen := map[string]bool{}
	for _, n := range p.Nodes {
		if seen[n] {
			t.Fatalf("path %s repeats node %s", p.ID, n)
		}
		seen[n] = true
	}
}

func assertPlanCutsAll(t *testing.T, paths []Path, plan []FixStep) {
	t.Helper()
	cut := map[string]bool{}
	for _, s := range plan {
		cut[s.EdgeID] = true
	}
	for _, p := range paths {
		hit := false
		for _, e := range p.Edges {
			hit = hit || cut[e]
		}
		if !hit {
			t.Fatalf("fix plan leaves path %s uncut", p.ID)
		}
	}
}

func countFrom(paths []Path, src string) int {
	n := 0
	for _, p := range paths {
		if p.Source == src {
			n++
		}
	}
	return n
}

func TestPropertiesOnRandomGraphs(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		seed := rapid.Int64().Draw(rt, "seed")
		n := rapid.IntRange(2, 60).Draw(rt, "nodes")
		depth := rapid.IntRange(1, 6).Draw(rt, "depth")
		k := rapid.IntRange(1, 4).Draw(rt, "k")
		g := randomGraph(seed, n, 1.5)
		paths := Enumerate(g, PathOptions{K: k, MaxDepth: depth})
		perSource := map[string]int{}
		for _, p := range paths {
			perSource[p.Source]++
			if p.Length() > depth {
				rt.Fatalf("path longer than depth %d", depth)
			}
			if g.Node(p.Target).Kind != graph.NodeTier0Sink {
				rt.Fatalf("path does not end at a sink")
			}
			seen := map[string]bool{}
			for i, eid := range p.Edges {
				e := g.Edge(eid)
				if e == nil || e.From != p.Nodes[i] || e.To != p.Nodes[i+1] || !usable(e) {
					rt.Fatalf("path %s has an invalid edge at %d", p.ID, i)
				}
				if seen[p.Nodes[i]] {
					rt.Fatalf("path %s is not simple", p.ID)
				}
				seen[p.Nodes[i]] = true
			}
		}
		for src, c := range perSource {
			if c > k {
				rt.Fatalf("%s has %d paths, K=%d", src, c, k)
			}
		}
		// Removing the plan's edges leaves no enumerated path intact.
		plan := FixPlan(paths, nil)
		removed := map[string]bool{}
		for _, s := range plan {
			removed[s.EdgeID] = true
		}
		for _, p := range paths {
			intact := true
			for _, e := range p.Edges {
				if removed[e] {
					intact = false
				}
			}
			if intact {
				rt.Fatalf("plan does not cut %s", p.ID)
			}
		}
		if after := Enumerate(g.RemoveEdges(removed), PathOptions{K: k, MaxDepth: depth}); len(after) > 0 {
			for _, p := range after {
				for _, q := range paths {
					if p.ID == q.ID {
						rt.Fatalf("path %s survives the plan", p.ID)
					}
				}
			}
		}
	})
}

func TestAnalysesAreDeterministic(t *testing.T) {
	g := randomGraph(42, 300, 2)
	first := Enumerate(g, PathOptions{})
	plan := FixPlan(first, nil)
	cps := ChokePoints(first)
	cycles := Cycles(g)
	for i := 0; i < 50; i++ {
		again := randomGraph(42, 300, 2)
		p := Enumerate(again, PathOptions{})
		if !reflect.DeepEqual(p, first) || !reflect.DeepEqual(FixPlan(p, nil), plan) ||
			!reflect.DeepEqual(ChokePoints(p), cps) || !reflect.DeepEqual(Cycles(again), cycles) {
			t.Fatalf("run %d differs", i)
		}
	}
}

func benchmarkEnumerate(b *testing.B, n int) {
	g := randomGraph(7, n, 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Enumerate(g, PathOptions{})
	}
}

func BenchmarkEnumerate1k(b *testing.B)  { benchmarkEnumerate(b, 1000) }
func BenchmarkEnumerate10k(b *testing.B) { benchmarkEnumerate(b, 10000) }
func BenchmarkEnumerate50k(b *testing.B) { benchmarkEnumerate(b, 50000) }

func BenchmarkCycles50k(b *testing.B) {
	g := randomGraph(7, 50000, 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Cycles(g)
	}
}
