// Command gen-attack extracts the active Enterprise ATT&CK techniques for
// the IaaS platform from the pinned STIX bundle and writes
// internal/attack/data/attack.json (ADR 0021). It runs at development time
// only (make gen); scans never download anything.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/brennocm/escalint/internal/attack"
)

// The pinned release. Changing it is a reviewed decision (ADR 0021).
const (
	version   = "20.0"
	bundleURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.0.json"
	bundleSHA = "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"
	maxBundle = 200 << 20
)

func main() {
	out := flag.String("out", "internal/attack/data/attack.json", "output file")
	in := flag.String("bundle", "", "read the bundle from a local file instead of downloading it")
	flag.Parse()
	if err := run(*in, *out); err != nil {
		fmt.Fprintf(os.Stderr, "gen-attack: %v\n", err)
		os.Exit(1)
	}
}

func run(in, out string) error {
	var raw []byte
	var err error
	if in != "" {
		raw, err = os.ReadFile(in) // #nosec G304 -- developer-chosen path
	} else {
		raw, err = download(bundleURL)
	}
	if err != nil {
		return err
	}
	file, err := extract(raw, bundleSHA)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(file, "", " ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(out, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s: ATT&CK %s, %d IaaS techniques\n", out, file.Version, len(file.Techniques))
	return nil
}

func download(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBundle+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBundle {
		return nil, errors.New("bundle larger than expected")
	}
	return body, nil
}

type stixObject struct {
	Type       string   `json:"type"`
	Name       string   `json:"name"`
	Revoked    bool     `json:"revoked"`
	Deprecated bool     `json:"x_mitre_deprecated"`
	Platforms  []string `json:"x_mitre_platforms"`
	Shortname  string   `json:"x_mitre_shortname"`
	Version    string   `json:"x_mitre_version"`
	Phases     []struct {
		KillChain string `json:"kill_chain_name"`
		Phase     string `json:"phase_name"`
	} `json:"kill_chain_phases"`
	References []struct {
		Source     string `json:"source_name"`
		ExternalID string `json:"external_id"`
		URL        string `json:"url"`
	} `json:"external_references"`
}

// extract verifies the bundle hash and keeps active IaaS techniques.
func extract(raw []byte, wantSHA string) (*attack.File, error) {
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != wantSHA {
		return nil, fmt.Errorf("bundle SHA-256 %s does not match the pinned %s", got, wantSHA)
	}
	var bundle struct {
		Objects []stixObject `json:"objects"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	tactics := map[string]string{}
	names := map[string]string{} // technique ID -> name, for sub-technique labels
	release := ""
	for _, o := range bundle.Objects {
		switch o.Type {
		case "x-mitre-tactic":
			tactics[o.Shortname] = o.Name
		case "x-mitre-collection":
			release = o.Version
		case "attack-pattern":
			if id := externalID(o); id != "" {
				names[id] = o.Name
			}
		}
	}
	if release != version {
		return nil, fmt.Errorf("bundle is ATT&CK %q, expected %s", release, version)
	}
	file := &attack.File{Version: version, Source: bundleURL, SHA256: wantSHA}
	for _, o := range bundle.Objects {
		id := externalID(o)
		if o.Type != "attack-pattern" || id == "" || o.Revoked || o.Deprecated || !contains(o.Platforms, "IaaS") {
			continue
		}
		t := attack.Technique{ID: id, Name: o.Name, URL: techniqueURL(o)}
		if parent, _, isSub := strings.Cut(id, "."); isSub && names[parent] != "" {
			t.Name = names[parent] + ": " + o.Name
		}
		for _, p := range o.Phases {
			if p.KillChain == "mitre-attack" {
				if name, ok := tactics[p.Phase]; ok {
					t.Tactics = append(t.Tactics, name)
				}
			}
		}
		sort.Strings(t.Tactics)
		file.Techniques = append(file.Techniques, t)
	}
	sort.Slice(file.Techniques, func(i, j int) bool { return file.Techniques[i].ID < file.Techniques[j].ID })
	return file, nil
}

func externalID(o stixObject) string {
	for _, r := range o.References {
		if r.Source == "mitre-attack" {
			return r.ExternalID
		}
	}
	return ""
}

func techniqueURL(o stixObject) string {
	for _, r := range o.References {
		if r.Source == "mitre-attack" {
			return r.URL
		}
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
