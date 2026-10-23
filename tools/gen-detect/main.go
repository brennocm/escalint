// Command gen-detect checks the hand-reviewed CloudTrail overrides against
// the AWS service reference and writes internal/detect/data/detect.json
// (ADR 0022): for every action it records the API operations that authorize
// it, and it fails when an override names an operation the service does not
// have. Development time only (make gen).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/brennocm/escalint/internal/detect"
)

const (
	referenceBase = "https://servicereference.us-east-1.amazonaws.com/v1/"
	maxService    = 32 << 20
)

var sourcePattern = regexp.MustCompile(`^[a-z0-9-]+\.amazonaws\.com$`)

type operationsFor func(service string) (map[string][]string, error) // action name -> operations

func main() {
	overrides := flag.String("overrides", "internal/detect/data/overrides.json", "reviewed overrides")
	out := flag.String("out", "internal/detect/data/detect.json", "output file")
	flag.Parse()
	client := &http.Client{Timeout: time.Minute}
	fetch := func(service string) (map[string][]string, error) { return downloadOperations(client, service) }
	if err := run(*overrides, *out, fetch); err != nil {
		fmt.Fprintf(os.Stderr, "gen-detect: %v\n", err)
		os.Exit(1)
	}
}

func run(overridesPath, out string, fetch operationsFor) error {
	raw, err := os.ReadFile(overridesPath) // #nosec G304 -- developer-chosen path
	if err != nil {
		return err
	}
	var f detect.File
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("overrides: %w", err)
	}
	if err := enrich(&f, fetch); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(out, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s: %d actions\n", out, len(f.Actions))
	return nil
}

// enrich validates every override and fills Operations.
func enrich(f *detect.File, fetch operationsFor) error {
	cache := map[string]map[string][]string{}
	var errs []error
	for i := range f.Actions {
		a := &f.Actions[i]
		service, name, ok := strings.Cut(a.Action, ":")
		if !ok {
			errs = append(errs, fmt.Errorf("action %q has no service prefix", a.Action))
			continue
		}
		if a.Status != detect.Verified && a.Status != detect.Experimental {
			errs = append(errs, fmt.Errorf("%s: invalid status %q", a.Action, a.Status))
		}
		ops, cached := cache[service]
		if !cached {
			var err error
			ops, err = fetch(service)
			if err != nil {
				return fmt.Errorf("service %s: %w", service, err)
			}
			cache[service] = ops
		}
		authorizing := ops[strings.ToLower(name)]
		a.Operations = authorizing
		if len(a.Events) > 0 && a.ReferenceGap == "" && !containsFold(authorizing, a.Operation) {
			errs = append(errs, fmt.Errorf("%s: operation %q does not authorize the action (service reference: %v)", a.Action, a.Operation, authorizing))
		}
		for _, e := range a.Events {
			switch {
			case !sourcePattern.MatchString(e.Source):
				errs = append(errs, fmt.Errorf("%s: eventSource %q is not <service>.amazonaws.com", a.Action, e.Source))
			case e.Kind != detect.Management && e.Kind != detect.Data:
				errs = append(errs, fmt.Errorf("%s: event kind %q", a.Action, e.Kind))
			case e.Source == service+".amazonaws.com" && !strings.HasPrefix(strings.ToLower(e.Name), strings.ToLower(a.Operation)):
				// Event names are the operation name, sometimes with a version
				// suffix (Lambda: CreateFunction20150331).
				errs = append(errs, fmt.Errorf("%s: event %q does not start with operation %q", a.Action, e.Name, a.Operation))
			}
		}
		if len(a.Events) == 0 && len(a.BlindSpots) == 0 {
			errs = append(errs, fmt.Errorf("%s: needs an event or an explicit blind spot", a.Action))
		}
	}
	sort.Slice(f.Actions, func(i, j int) bool { return f.Actions[i].Action < f.Actions[j].Action })
	return errors.Join(errs...)
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// downloadOperations maps each action of a service to the operations that
// authorize it, from Operations[].AuthorizedActions.
func downloadOperations(client *http.Client, service string) (map[string][]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	url := referenceBase + service + "/" + service + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxService+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxService {
		return nil, errors.New("service reference too large")
	}
	return parseOperations(body, service)
}

func parseOperations(body []byte, service string) (map[string][]string, error) {
	var ref struct {
		Operations []struct {
			Name              string `json:"Name"`
			AuthorizedActions []struct {
				Name    string `json:"Name"`
				Service string `json:"Service"`
			} `json:"AuthorizedActions"`
		} `json:"Operations"`
	}
	if err := json.Unmarshal(body, &ref); err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, op := range ref.Operations {
		for _, a := range op.AuthorizedActions {
			if a.Service == service {
				key := strings.ToLower(a.Name)
				out[key] = append(out[key], op.Name)
			}
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out, nil
}
