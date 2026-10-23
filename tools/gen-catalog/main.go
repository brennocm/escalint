// Command gen-catalog downloads the AWS service reference and writes the
// action catalog embedded by internal/catalog.
//
// It runs only at development time (make gen / go generate), never during a
// scan. The index lists one URL per service; those URLs are only followed
// when they use the same scheme and host as the index itself, so a tampered
// index cannot make the tool fetch from elsewhere. The command line only
// accepts an HTTPS index on the official host (tests call build directly
// with a local server). Responses are size-limited.
//
// Usage: go run ./tools/gen-catalog -out internal/catalog/data/catalog.json.gz
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/brennocm/escalint/internal/catalog"
)

const (
	defaultIndex   = "https://servicereference.us-east-1.amazonaws.com/"
	referenceHost  = "servicereference.us-east-1.amazonaws.com"
	maxIndexBytes  = 4 << 20
	maxServiceSize = 32 << 20
)

var (
	servicePrefix = regexp.MustCompile(`^[a-z0-9-]+$`)
	actionName    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

func main() {
	index := flag.String("index", defaultIndex, "service reference index URL")
	out := flag.String("out", "internal/catalog/data/catalog.json.gz", "output file")
	date := flag.String("date", time.Now().UTC().Format("2006-01-02"), "generation date recorded in the file")
	workers := flag.Int("workers", 8, "parallel downloads")
	timeout := flag.Duration("timeout", 5*time.Minute, "overall timeout")
	flag.Parse()

	if err := checkIndexURL(*index, referenceHost); err != nil {
		fmt.Fprintf(os.Stderr, "gen-catalog: %v\n", err)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := run(ctx, &http.Client{Timeout: time.Minute}, *index, *out, *date, *workers); err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "gen-catalog: %v\n", err)
		os.Exit(1) //nolint:gocritic // cancel already called above
	}
}

func run(ctx context.Context, client *http.Client, index, out, date string, workers int) error {
	file, err := build(ctx, client, index, date, workers)
	if err != nil {
		return err
	}
	data, err := encode(file)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	actions := 0
	for _, s := range file.Services {
		actions += len(s.Actions)
	}
	fmt.Printf("wrote %s: %d services, %d actions, %d bytes\n", out, len(file.Services), actions, len(data))
	return nil
}

type indexEntry struct {
	Service  string `json:"service"`
	URL      string `json:"url"`
	Modified int64  `json:"modified"`
}

// Only the fields the catalog needs; everything else is ignored.
type serviceReference struct {
	Name    string `json:"Name"`
	Version string `json:"Version"`
	Actions []struct {
		Name        string `json:"Name"`
		Annotations struct {
			Properties struct {
				IsList                 bool `json:"IsList"`
				IsPermissionManagement bool `json:"IsPermissionManagement"`
				IsTaggingOnly          bool `json:"IsTaggingOnly"`
				IsWrite                bool `json:"IsWrite"`
			} `json:"Properties"`
		} `json:"Annotations"`
		Resources []struct {
			Name string `json:"Name"`
		} `json:"Resources"`
	} `json:"Actions"`
	Resources []struct {
		Name       string   `json:"Name"`
		ARNFormats []string `json:"ARNFormats"`
	} `json:"Resources"`
}

func build(ctx context.Context, client *http.Client, index, date string, workers int) (*catalog.File, error) {
	var entries []indexEntry
	if err := fetchJSON(ctx, client, index, maxIndexBytes, &entries); err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("index is empty")
	}
	base, err := url.Parse(index)
	if err != nil {
		return nil, fmt.Errorf("index URL: %w", err)
	}
	for _, e := range entries {
		if err := checkEntry(e, base); err != nil {
			return nil, err
		}
	}

	services := make([]catalog.FileService, len(entries))
	errs := make([]error, len(entries))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < max(1, workers); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				services[i], errs[i] = fetchService(ctx, client, entries[i])
			}
		}()
	}
	for i := range entries {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	sort.Slice(services, func(i, j int) bool { return services[i].Prefix < services[j].Prefix })
	for i := 1; i < len(services); i++ {
		if services[i].Prefix == services[i-1].Prefix {
			return nil, fmt.Errorf("service %q listed twice", services[i].Prefix)
		}
	}
	return &catalog.File{
		FormatVersion: catalog.FormatVersion,
		Source:        index,
		Generated:     date,
		Services:      services,
	}, nil
}

// checkIndexURL requires HTTPS on the official service reference host.
func checkIndexURL(index, host string) error {
	u, err := url.Parse(index)
	if err != nil || u.Scheme != "https" || u.Host != host {
		return fmt.Errorf("index %q must be https://%s/", index, host)
	}
	return nil
}

// checkEntry validates a service entry and requires its URL to stay on the
// scheme and host of the index.
func checkEntry(e indexEntry, base *url.URL) error {
	if !servicePrefix.MatchString(e.Service) {
		return fmt.Errorf("index: invalid service prefix %q", e.Service)
	}
	u, err := url.Parse(e.URL)
	if err != nil || u.Scheme != base.Scheme || u.Host != base.Host {
		return fmt.Errorf("index: service %q has URL %q outside %s://%s", e.Service, e.URL, base.Scheme, base.Host)
	}
	return nil
}

func fetchService(ctx context.Context, client *http.Client, e indexEntry) (catalog.FileService, error) {
	var ref serviceReference
	if err := fetchJSON(ctx, client, e.URL, maxServiceSize, &ref); err != nil {
		return catalog.FileService{}, fmt.Errorf("service %s: %w", e.Service, err)
	}
	if ref.Name != e.Service {
		return catalog.FileService{}, fmt.Errorf("service %s: document is for %q", e.Service, ref.Name)
	}
	svc := catalog.FileService{Prefix: e.Service, Name: e.Service, Version: ref.Version, Modified: e.Modified}
	seen := map[string]bool{}
	for _, a := range ref.Actions {
		if !actionName.MatchString(a.Name) {
			return catalog.FileService{}, fmt.Errorf("service %s: invalid action name %q", e.Service, a.Name)
		}
		if seen[strings.ToLower(a.Name)] {
			return catalog.FileService{}, fmt.Errorf("service %s: action %q listed twice", e.Service, a.Name)
		}
		seen[strings.ToLower(a.Name)] = true
		p := a.Annotations.Properties
		action := catalog.FileAction{
			Name:   a.Name,
			Access: catalog.AccessFromAnnotations(p.IsPermissionManagement, p.IsTaggingOnly, p.IsWrite, p.IsList),
		}
		for _, r := range a.Resources {
			action.Resources = append(action.Resources, r.Name)
		}
		sort.Strings(action.Resources)
		svc.Actions = append(svc.Actions, action)
	}
	sort.Slice(svc.Actions, func(i, j int) bool { return svc.Actions[i].Name < svc.Actions[j].Name })
	for _, r := range ref.Resources {
		formats := append([]string(nil), r.ARNFormats...)
		sort.Strings(formats)
		svc.Resources = append(svc.Resources, catalog.FileResource{Name: r.Name, ARNFormats: formats})
	}
	sort.Slice(svc.Resources, func(i, j int) bool { return svc.Resources[i].Name < svc.Resources[j].Name })
	return svc, nil
}

func fetchJSON(ctx context.Context, client *http.Client, rawURL string, limit int64, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("GET %s: %w", rawURL, err)
	}
	if int64(len(body)) > limit {
		return fmt.Errorf("GET %s: response larger than %d bytes", rawURL, limit)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("GET %s: %w", rawURL, err)
	}
	return nil
}

// encode writes deterministic gzip: no file name, zero modification time and
// a fixed compression level, so the same catalog gives the same bytes.
func encode(file *catalog.File) ([]byte, error) {
	data, err := json.Marshal(file)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
