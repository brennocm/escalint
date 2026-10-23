package rules

import (
	_ "embed"
	"encoding/json"
	"sync"
)

//go:embed data/pathfinding.json
var pathfindingJSON []byte

// PathfindingPath is one AWS path of pathfinding.cloud (Apache-2.0): only
// its ID, name, category and links are embedded.
type PathfindingPath struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	URL      string `json:"url"`
	Source   string `json:"source"`
}

type pathfindingFile struct {
	Commit string            `json:"commit"`
	Paths  []PathfindingPath `json:"paths"`
}

var pathfindingData = sync.OnceValue(func() pathfindingFile {
	var f pathfindingFile
	if err := json.Unmarshal(pathfindingJSON, &f); err != nil {
		panic("rules: embedded pathfinding.json is invalid: " + err.Error()) // build-time data, covered by tests
	}
	return f
})

// PathfindingCommit is the pathfinding.cloud commit the data comes from.
func PathfindingCommit() string { return pathfindingData().Commit }

// Pathfinding lists the verified pathfinding.cloud AWS paths, by ID.
var Pathfinding = sync.OnceValue(func() map[string]PathfindingPath {
	f := pathfindingData()
	out := make(map[string]PathfindingPath, len(f.Paths))
	for _, p := range f.Paths {
		out[p.ID] = p
	}
	return out
})
