package analysis

import (
	"math/bits"
	"sort"

	"github.com/brennocm/escalint/internal/graph"
)

// BlastAll computes the blast radius of every user, role and group node at
// once. One breadth-first search per node is quadratic on dense graphs
// (an actor with iam:CreateAccessKey on user/* reaches every user), so this
// condenses the graph into strongly connected components and combines
// reachable sets bottom-up: bitsets for reachable principals, best class per
// service for capabilities. Reach is transitive (no depth limit): an
// attacker is not limited to the path enumeration depth (ADR 0008
// amendment). A component's data is freed once every predecessor used it.
func BlastAll(g *graph.Graph, finder *CapabilityFinder) map[string]Blast {
	nodes := g.Nodes()
	index := make(map[string]int32, len(nodes))
	for i, n := range nodes {
		index[n.ID] = int32(i)
	}
	adj := make([][]int32, len(nodes))
	for i, n := range nodes {
		for _, e := range g.Out(n.ID) {
			if usable(e) {
				adj[i] = append(adj[i], index[e.To])
			}
		}
	}

	// Principals get bit positions; services get capability slots.
	principal := make([]int32, len(nodes)) // bit index or -1
	var nPrincipals int32
	for i, n := range nodes {
		principal[i] = -1
		if isPrincipal(n) {
			principal[i] = nPrincipals
			nPrincipals++
		}
	}
	words := (int(nPrincipals) + 63) / 64
	services := map[string]int{}
	var serviceNames []string
	own := make([][]capEntry, len(nodes))
	for i, n := range nodes {
		if !isPrincipal(n) {
			continue
		}
		caps := finder.For(n.ID)
		svcs := make([]string, 0, len(caps))
		for svc := range caps {
			svcs = append(svcs, svc)
		}
		sort.Strings(svcs)
		for _, svc := range svcs {
			slot, ok := services[svc]
			if !ok {
				slot = len(serviceNames)
				services[svc] = slot
				serviceNames = append(serviceNames, svc)
			}
			own[i] = append(own[i], capEntry{slot: slot, rank: classRank[caps[svc]]})
		}
	}

	comp, comps := tarjanInt(adj)
	// Count distinct predecessor components to free data early.
	succs := make([][]int32, len(comps))
	preds := make([]int, len(comps))
	for c, members := range comps {
		seen := map[int32]bool{}
		for _, v := range members {
			for _, w := range adj[v] {
				d := comp[w]
				if d != int32(c) && !seen[d] {
					seen[d] = true
					succs[c] = append(succs[c], d)
					preds[d]++
				}
			}
		}
	}

	type compData struct {
		reach []uint64 // principals reachable from the component (members of a cycle included)
		caps  []int8   // best rank per service slot over that set, -1 none
		tier0 bool
	}
	data := make([]*compData, len(comps))
	none := int8(-1)
	newCaps := func() []int8 {
		c := make([]int8, len(serviceNames))
		for i := range c {
			c[i] = none
		}
		return c
	}
	merge := func(dst []int8, src []int8) {
		for i, r := range src {
			if r != none && (dst[i] == none || r < dst[i]) {
				dst[i] = r
			}
		}
	}
	addMember := func(d *compData, v int32) {
		if b := principal[v]; b >= 0 {
			d.reach[b/64] |= 1 << (uint(b) % 64)
		}
		for _, ce := range own[v] {
			if d.caps[ce.slot] == none || ce.rank < d.caps[ce.slot] {
				d.caps[ce.slot] = ce.rank
			}
		}
		if n := nodes[v]; n.Kind == graph.NodeTier0Sink || (isPrincipal(n) && n.Tier == 0) {
			d.tier0 = true
		}
	}

	out := make(map[string]Blast, nPrincipals)
	// Tarjan emits components in reverse topological order: successors
	// first.
	for c, members := range comps {
		d := &compData{reach: make([]uint64, words), caps: newCaps()}
		for _, s := range succs[c] {
			sd := data[s]
			for i, w := range sd.reach {
				d.reach[i] |= w
			}
			merge(d.caps, sd.caps)
			d.tier0 = d.tier0 || sd.tier0
			if preds[s]--; preds[s] == 0 {
				data[s] = nil
			}
		}
		// Members of a cycle reach each other (and themselves).
		cyclic := len(members) > 1 || selfLoop(adj, members[0])
		if cyclic {
			for _, v := range members {
				addMember(d, v)
			}
		}
		for _, v := range members {
			n := nodes[v]
			if !isPrincipal(n) {
				continue
			}
			count := 0
			for _, w := range d.reach {
				count += bits.OnesCount64(w)
			}
			if b := principal[v]; cyclic && b >= 0 {
				count-- // the node itself
			}
			best := append([]int8(nil), d.caps...)
			for _, ce := range own[v] {
				if best[ce.slot] == none || ce.rank < best[ce.slot] {
					best[ce.slot] = ce.rank
				}
			}
			b := Blast{ReachablePrincipals: count, ReachesTier0: d.tier0 || n.Tier == 0, Capabilities: map[Class][]string{}}
			for slot, r := range best {
				if r != none {
					cls := classOrder[r]
					b.Capabilities[cls] = append(b.Capabilities[cls], serviceNames[slot])
				}
			}
			for _, list := range b.Capabilities {
				sort.Strings(list)
			}
			out[n.ID] = b
		}
		// What predecessors inherit: this component's reach plus its
		// members (when not already added as a cycle).
		if !cyclic {
			for _, v := range members {
				addMember(d, v)
			}
		}
		if preds[c] > 0 {
			data[c] = d
		}
	}
	return out
}

// classRank is the position of a class in classOrder (strongest first).
var classRank = map[Class]int8{ClassPermissionManagement: 0, ClassWrite: 1, ClassRead: 2, ClassList: 3}

type capEntry struct {
	slot int
	rank int8
}

func isPrincipal(n *graph.Node) bool {
	return n.Kind == graph.NodeUser || n.Kind == graph.NodeRole || n.Kind == graph.NodeGroup
}

func selfLoop(adj [][]int32, v int32) bool {
	for _, w := range adj[v] {
		if w == v {
			return true
		}
	}
	return false
}

// tarjanInt is iterative Tarjan on an int adjacency list. It returns the
// component of each vertex and the components in the order they complete
// (reverse topological order of the condensation).
func tarjanInt(adj [][]int32) (comp []int32, comps [][]int32) {
	n := len(adj)
	idx := make([]int32, n)
	low := make([]int32, n)
	onStack := make([]bool, n)
	comp = make([]int32, n)
	for i := range idx {
		idx[i] = -1
	}
	var stack []int32
	var counter, nComps int32
	type frame struct {
		v    int32
		next int
	}
	for root := range n {
		if idx[root] >= 0 {
			continue
		}
		call := []frame{{v: int32(root)}}
		idx[root], low[root] = counter, counter
		counter++
		stack = append(stack, int32(root))
		onStack[root] = true
		for len(call) > 0 {
			f := &call[len(call)-1]
			v := f.v
			if f.next < len(adj[v]) {
				w := adj[v][f.next]
				f.next++
				switch {
				case idx[w] < 0:
					idx[w], low[w] = counter, counter
					counter++
					stack = append(stack, w)
					onStack[w] = true
					call = append(call, frame{v: w})
				case onStack[w] && idx[w] < low[v]:
					low[v] = idx[w]
				}
				continue
			}
			call = call[:len(call)-1]
			if len(call) > 0 {
				if p := call[len(call)-1].v; low[v] < low[p] {
					low[p] = low[v]
				}
			}
			if low[v] == idx[v] {
				var members []int32
				for {
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					comp[w] = nComps
					members = append(members, w)
					if w == v {
						break
					}
				}
				comps = append(comps, members)
				nComps++
			}
		}
	}
	return comp, comps
}
