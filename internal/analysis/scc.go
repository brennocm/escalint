package analysis

import (
	"sort"

	"github.com/brennocm/escalint/internal/graph"
)

// Cycles returns the strongly connected components with two or more nodes
// (circular chains such as roles that can assume each other), using an
// iterative Tarjan so long chains cannot overflow the stack. Each component
// is sorted by node ID; components are sorted by their first ID.
func Cycles(g *graph.Graph) [][]string {
	index := map[string]int{}
	low := map[string]int{}
	onStack := map[string]bool{}
	var stack []string
	var out [][]string
	next := 0

	type frame struct {
		node  string
		edges []*graph.Edge
		i     int
	}
	for _, start := range g.Nodes() {
		if _, done := index[start.ID]; done {
			continue
		}
		work := []frame{{node: start.ID, edges: g.Out(start.ID)}}
		index[start.ID], low[start.ID] = next, next
		next++
		stack = append(stack, start.ID)
		onStack[start.ID] = true

		for len(work) > 0 {
			top := &work[len(work)-1]
			if top.i < len(top.edges) {
				e := top.edges[top.i]
				top.i++
				if !usable(e) {
					continue
				}
				w := e.To
				if _, seen := index[w]; !seen {
					index[w], low[w] = next, next
					next++
					stack = append(stack, w)
					onStack[w] = true
					work = append(work, frame{node: w, edges: g.Out(w)})
				} else if onStack[w] && index[w] < low[top.node] {
					low[top.node] = index[w]
				}
				continue
			}
			v := top.node
			work = work[:len(work)-1]
			if len(work) > 0 {
				parent := work[len(work)-1].node
				if low[v] < low[parent] {
					low[parent] = low[v]
				}
			}
			if low[v] == index[v] {
				var comp []string
				for {
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					comp = append(comp, w)
					if w == v {
						break
					}
				}
				if len(comp) > 1 {
					sort.Strings(comp)
					out = append(out, comp)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}
