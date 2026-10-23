// Package detect tells, for each exploitation step, which CloudTrail events
// it produces and what CloudTrail cannot see (ADR 0022). The data is the
// hand-reviewed data/overrides.json, checked against the AWS service
// reference and enriched by tools/gen-detect into data/detect.json.
package detect

//go:generate go run ../../tools/gen-detect -overrides data/overrides.json -out data/detect.json

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed data/detect.json
var embedded []byte

// EventKind distinguishes CloudTrail management and data events.
type EventKind string

// Event kinds.
const (
	Management EventKind = "management"
	Data       EventKind = "data"
)

// Status of a detection hint.
type Status string

// Statuses: verified hints were confirmed in the service's CloudTrail
// documentation; experimental ones are inferred.
const (
	Verified     Status = "verified"
	Experimental Status = "experimental"
)

// Visibility summarizes a step for the UI (shape-coded indicator).
type Visibility string

// Visibilities.
const (
	Visible Visibility = "visible"
	Partial Visibility = "partial"
	Blind   Visibility = "blind"
)

// Event is one CloudTrail event a step produces.
type Event struct {
	Source    string    `json:"source"` // eventSource, e.g. "iam.amazonaws.com"
	Name      string    `json:"name"`   // eventName, e.g. "CreatePolicyVersion"
	Kind      EventKind `json:"kind"`
	KeyFields []string  `json:"key_fields"`
	Region    string    `json:"region"`
	Notes     string    `json:"notes,omitempty"`
}

// ActionDetection is the detection data of one IAM action.
type ActionDetection struct {
	Action             string   `json:"action"`
	Operation          string   `json:"operation"`  // API operation that authorizes the action
	Operations         []string `json:"operations"` // every operation authorizing it (service reference)
	Events             []Event  `json:"events"`
	BlindSpots         []string `json:"blind_spots"`
	RequiresDataEvents bool     `json:"requires_data_events"`
	Status             Status   `json:"status"`
	// ReferenceGap explains why the service reference cannot confirm the
	// operation (for example unauthenticated STS calls). Required to skip
	// the operation check in tools/gen-detect.
	ReferenceGap string `json:"reference_gap,omitempty"`
}

// EdgeKindHints are blind spots that apply to every step of a kind.
type EdgeKindHints struct {
	BlindSpots []string `json:"blind_spots"`
	Structural bool     `json:"structural,omitempty"`
}

// File is the detect.json (and overrides.json) document.
type File struct {
	FormatVersion int                      `json:"format_version"`
	Sources       []string                 `json:"sources"`
	Actions       []ActionDetection        `json:"actions"`
	EdgeKinds     map[string]EdgeKindHints `json:"edge_kinds"`
}

// Catalog indexes detection data.
type Catalog struct {
	actions map[string]ActionDetection
	kinds   map[string]EdgeKindHints
}

// Default returns the embedded catalog, decoded once.
func Default() (*Catalog, error) { return loadDefault() }

var loadDefault = sync.OnceValues(func() (*Catalog, error) { return Decode(embedded) })

// Decode parses a detect.json document.
func Decode(raw []byte) (*Catalog, error) {
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("detect: %w", err)
	}
	c := &Catalog{actions: map[string]ActionDetection{}, kinds: f.EdgeKinds}
	for _, a := range f.Actions {
		key := strings.ToLower(a.Action)
		if _, dup := c.actions[key]; dup {
			return nil, fmt.Errorf("detect: action %s appears twice", a.Action)
		}
		c.actions[key] = a
	}
	return c, nil
}

// Action returns the detection data of an action.
func (c *Catalog) Action(action string) (ActionDetection, bool) {
	a, ok := c.actions[strings.ToLower(action)]
	return a, ok
}

// EdgeKind returns the hints of an edge kind.
func (c *Catalog) EdgeKind(kind string) (EdgeKindHints, bool) {
	h, ok := c.kinds[kind]
	return h, ok
}

// Step is the detection view of one edge.
type Step struct {
	Events             []Event
	BlindSpots         []string
	RequiresDataEvents bool
	Status             Status
	Visibility         Visibility
}

// ForStep combines the hints of an edge kind and the actions it requires.
// Unknown actions add an explicit blind spot and make the step experimental.
func (c *Catalog) ForStep(kind string, actions []string) Step {
	s := Step{Status: Verified}
	seenEvent := map[string]bool{}
	seenBlind := map[string]bool{}
	addBlind := func(b string) {
		if !seenBlind[b] {
			seenBlind[b] = true
			s.BlindSpots = append(s.BlindSpots, b)
		}
	}
	if h, ok := c.kinds[kind]; ok {
		for _, b := range h.BlindSpots {
			addBlind(b)
		}
		if h.Structural {
			return Step{Status: Verified, Visibility: Visible}
		}
	}
	for _, action := range actions {
		a, ok := c.actions[strings.ToLower(action)]
		if !ok {
			addBlind("No detection data for " + action + ".")
			s.Status = Experimental
			continue
		}
		for _, e := range a.Events {
			key := e.Source + "/" + e.Name
			if !seenEvent[key] {
				seenEvent[key] = true
				s.Events = append(s.Events, e)
			}
		}
		for _, b := range a.BlindSpots {
			addBlind(b)
		}
		s.RequiresDataEvents = s.RequiresDataEvents || a.RequiresDataEvents
		if a.Status == Experimental {
			s.Status = Experimental
		}
	}
	sort.SliceStable(s.Events, func(i, j int) bool {
		if s.Events[i].Source != s.Events[j].Source {
			return s.Events[i].Source < s.Events[j].Source
		}
		return s.Events[i].Name < s.Events[j].Name
	})
	sort.Strings(s.BlindSpots)
	s.Visibility = visibility(s)
	return s
}

func visibility(s Step) Visibility {
	management := 0
	for _, e := range s.Events {
		if e.Kind == Management {
			management++
		}
	}
	switch {
	case management == 0:
		return Blind
	case len(s.BlindSpots) > 0 || s.RequiresDataEvents:
		return Partial
	default:
		return Visible
	}
}
