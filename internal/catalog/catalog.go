// Package catalog exposes the AWS action catalog embedded in the binary.
//
// The data comes from the AWS service reference (docs/research.md §12) and is
// regenerated with `make gen` by tools/gen-catalog. Scans never download
// anything: they only read data/catalog.json.gz.
package catalog

//go:generate go run ../../tools/gen-catalog -out data/catalog.json.gz

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/brennocm/escalint/internal/match"
)

//go:embed data/catalog.json.gz
var embedded []byte

// Action is one IAM action.
type Action struct {
	Service   string // prefix, e.g. "iam"
	Name      string // e.g. "PassRole", as spelled by AWS
	Access    AccessLevel
	Resources []string // resource types the action authorizes
}

// String returns "service:Name".
func (a Action) String() string {
	return a.Service + ":" + a.Name
}

// Service is one service prefix and its actions, sorted by name.
type Service struct {
	Prefix   string
	Version  string
	Modified int64
	Actions  []Action
}

// Catalog is an immutable, indexed view of a catalog file.
type Catalog struct {
	Source    string
	Generated string
	services  []*Service
	byPrefix  map[string]*Service
	byAction  map[string]Action // key: lower-case "service:name"
	actionCnt int
}

// Default returns the embedded catalog. It is decoded once and shared; the
// returned value must not be modified.
func Default() (*Catalog, error) {
	return loadDefault()
}

var loadDefault = sync.OnceValues(func() (*Catalog, error) {
	return Decode(bytes.NewReader(embedded))
})

// Decode reads a gzip-compressed catalog file.
func Decode(r io.Reader) (*Catalog, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	defer zr.Close()
	var f File
	if err := json.NewDecoder(zr).Decode(&f); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	return New(&f)
}

// New indexes a catalog file and validates it.
func New(f *File) (*Catalog, error) {
	if f.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("catalog: format version %d is not supported (want %d)", f.FormatVersion, FormatVersion)
	}
	c := &Catalog{
		Source:    f.Source,
		Generated: f.Generated,
		byPrefix:  map[string]*Service{},
		byAction:  map[string]Action{},
	}
	for _, fs := range f.Services {
		if _, dup := c.byPrefix[fs.Prefix]; dup {
			return nil, fmt.Errorf("catalog: service %q appears twice", fs.Prefix)
		}
		svc := &Service{Prefix: fs.Prefix, Version: fs.Version, Modified: fs.Modified}
		for _, fa := range fs.Actions {
			a := Action{Service: fs.Prefix, Name: fa.Name, Access: fa.Access, Resources: fa.Resources}
			key := strings.ToLower(a.String())
			if _, dup := c.byAction[key]; dup {
				return nil, fmt.Errorf("catalog: action %q appears twice", a)
			}
			c.byAction[key] = a
			svc.Actions = append(svc.Actions, a)
		}
		sort.Slice(svc.Actions, func(i, j int) bool { return svc.Actions[i].Name < svc.Actions[j].Name })
		c.services = append(c.services, svc)
		c.byPrefix[fs.Prefix] = svc
		c.actionCnt += len(svc.Actions)
	}
	sort.Slice(c.services, func(i, j int) bool { return c.services[i].Prefix < c.services[j].Prefix })
	return c, nil
}

// Services returns every service, sorted by prefix.
func (c *Catalog) Services() []*Service {
	return c.services
}

// Service returns the service with the given prefix (case-insensitive).
func (c *Catalog) Service(prefix string) (*Service, bool) {
	s, ok := c.byPrefix[strings.ToLower(prefix)]
	return s, ok
}

// Len returns the number of actions.
func (c *Catalog) Len() int {
	return c.actionCnt
}

// Lookup finds an action by "service:Name", ignoring case as IAM does.
func (c *Catalog) Lookup(action string) (Action, bool) {
	a, ok := c.byAction[strings.ToLower(action)]
	return a, ok
}

// Expand returns every catalog action matched by an IAM action pattern such
// as "iam:Put*" or "*", sorted by service then name. A pattern whose service
// part has no wildcard only scans that service.
func (c *Catalog) Expand(pattern string) []Action {
	var candidates []*Service
	svcPart, _, hasColon := strings.Cut(pattern, ":")
	switch {
	case pattern == "*":
		candidates = c.services
	case !hasColon:
		return nil // not an action pattern
	case strings.ContainsAny(svcPart, "*?"):
		candidates = c.services
	default:
		if s, ok := c.Service(svcPart); ok {
			candidates = []*Service{s}
		}
	}
	var out []Action
	for _, s := range candidates {
		for _, a := range s.Actions {
			if match.Action(pattern, a.String()) {
				out = append(out, a)
			}
		}
	}
	return out
}
