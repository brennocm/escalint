package analysis

import "sort"

// ChokePoint is an edge and how many enumerated paths go through it.
type ChokePoint struct {
	EdgeID   string
	PathsCut int
	Share    float64 // PathsCut / total paths
}

// ChokePoints counts, for each edge, the enumerated paths that use it.
// Sorted by paths cut (descending) then edge ID.
func ChokePoints(paths []Path) []ChokePoint {
	count := map[string]int{}
	for _, p := range paths {
		seen := map[string]bool{}
		for _, e := range p.Edges {
			if !seen[e] {
				seen[e] = true
				count[e]++
			}
		}
	}
	out := make([]ChokePoint, 0, len(count))
	for id, n := range count {
		out = append(out, ChokePoint{EdgeID: id, PathsCut: n, Share: float64(n) / float64(len(paths))})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PathsCut != out[j].PathsCut {
			return out[i].PathsCut > out[j].PathsCut
		}
		return out[i].EdgeID < out[j].EdgeID
	})
	return out
}
