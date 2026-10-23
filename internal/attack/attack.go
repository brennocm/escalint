// Package attack exposes the MITRE ATT&CK techniques escalint can reference:
// every active (not revoked, not deprecated) Enterprise technique for the
// IaaS platform, extracted from the pinned STIX bundle by tools/gen-attack
// (ADR 0021). Rules name techniques by ID; names and tactics come from here.
//
// © 2026 The MITRE Corporation. This work is reproduced and distributed with
// the permission of The MITRE Corporation. MITRE ATT&CK and ATT&CK are
// registered trademarks of The MITRE Corporation. See data/LICENSE-MITRE.txt.
package attack

//go:generate go run ../../tools/gen-attack -out data/attack.json

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

//go:embed data/attack.json
var embedded []byte

// Technique is one ATT&CK technique or sub-technique.
type Technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`    // sub-techniques: "Parent: Child"
	Tactics []string `json:"tactics"` // display names, e.g. "Privilege Escalation"
	URL     string   `json:"url"`
}

// File is the embedded document.
type File struct {
	Version    string      `json:"version"` // ATT&CK release, e.g. "20.0"
	Source     string      `json:"source"`
	SHA256     string      `json:"sha256"` // of the STIX bundle
	Techniques []Technique `json:"techniques"`
}

// Data is the decoded file with an index.
type Data struct {
	Version    string
	Techniques []Technique // sorted by ID
	byID       map[string]Technique
}

// Default returns the embedded data, decoded once.
func Default() (*Data, error) { return loadDefault() }

var loadDefault = sync.OnceValues(func() (*Data, error) { return Decode(embedded) })

// Decode parses an attack.json document.
func Decode(raw []byte) (*Data, error) {
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("attack: %w", err)
	}
	d := &Data{Version: f.Version, Techniques: f.Techniques, byID: map[string]Technique{}}
	for _, t := range f.Techniques {
		if _, dup := d.byID[t.ID]; dup {
			return nil, fmt.Errorf("attack: technique %s appears twice", t.ID)
		}
		d.byID[t.ID] = t
	}
	sort.Slice(d.Techniques, func(i, j int) bool { return d.Techniques[i].ID < d.Techniques[j].ID })
	return d, nil
}

// Lookup returns an active IaaS technique by ID.
func (d *Data) Lookup(id string) (Technique, bool) {
	t, ok := d.byID[id]
	return t, ok
}
