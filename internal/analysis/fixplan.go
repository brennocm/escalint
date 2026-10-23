package analysis

import "sort"

// FixStep is one edge to remove and the enumerated paths it cuts that no
// earlier step already cut.
type FixStep struct {
	Order    int
	EdgeID   string
	PathsCut []string // path IDs, sorted
}

// FixPlan picks a small set of edges whose removal cuts every enumerated
// path. Minimum hitting set is NP-hard, so this is the classic greedy
// approximation (ADR 0009): repeatedly take the edge that cuts the most
// remaining paths, breaking ties by edge ID. Its result is within a factor
// of ln(n)+1 of optimal.
//
// Edges that cannot be fixed by changing a policy of the snapshot (admin
// edges: the principal is already an administrator) are never chosen unless
// a path has no other edge.
func FixPlan(paths []Path, fixable func(edgeID string) bool) []FixStep {
	remaining := map[string]Path{}
	for _, p := range paths {
		remaining[p.ID] = p
	}
	var plan []FixStep
	for len(remaining) > 0 {
		cuts := map[string][]string{}
		for id, p := range remaining {
			for _, e := range p.Edges {
				cuts[e] = append(cuts[e], id)
			}
		}
		best, bestFixable := "", false
		for e, ps := range cuts {
			f := fixable == nil || fixable(e)
			switch {
			case best == "":
			case f != bestFixable:
				if !f {
					continue
				}
			case len(ps) < len(cuts[best]):
				continue
			case len(ps) == len(cuts[best]) && e > best:
				continue
			}
			best, bestFixable = e, f
		}
		cut := cuts[best]
		sort.Strings(cut)
		for _, id := range cut {
			delete(remaining, id)
		}
		plan = append(plan, FixStep{Order: len(plan) + 1, EdgeID: best, PathsCut: cut})
	}
	return plan
}
