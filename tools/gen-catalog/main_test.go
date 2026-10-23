package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brennocm/escalint/internal/catalog"
)

// fakeReference serves an index and service documents. urlFor lets a test
// point an entry somewhere else.
func fakeReference(t *testing.T, services map[string]string, urlFor func(base, svc string) string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		var entries []indexEntry
		for name := range services {
			entries = append(entries, indexEntry{Service: name, URL: urlFor(srv.URL, name), Modified: 1700000000})
		}
		_ = json.NewEncoder(w).Encode(entries)
	})
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(filepath.Base(r.URL.Path), ".json")
		body, ok := services[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func sameHost(base, svc string) string { return fmt.Sprintf("%s/v1/%s/%s.json", base, svc, svc) }

const iamDoc = `{"Name":"iam","Version":"v1.5","Actions":[
 {"Name":"PutRolePolicy","Annotations":{"Properties":{"IsPermissionManagement":true,"IsWrite":true}},"Resources":[{"Name":"role"}]},
 {"Name":"GetRole","Annotations":{"Properties":{}}},
 {"Name":"ListRoles","Annotations":{"Properties":{"IsList":true}}}],
 "Resources":[{"Name":"role","ARNFormats":["arn:${Partition}:iam::${Account}:role/${RoleNameWithPath}"]}]}`

const s3Doc = `{"Name":"s3","Version":"v1.5","Actions":[{"Name":"GetObject","Annotations":{"Properties":{}}}]}`

func TestBuildAndEncode(t *testing.T) {
	srv := fakeReference(t, map[string]string{"s3": s3Doc, "iam": iamDoc}, sameHost)
	file, err := build(context.Background(), srv.Client(), srv.URL+"/", "2026-10-23", 2)
	if err != nil {
		t.Fatalf("build() error = %v", err)
	}
	if len(file.Services) != 2 || file.Services[0].Prefix != "iam" || file.Services[1].Prefix != "s3" {
		t.Fatalf("services not sorted: %+v", file.Services)
	}
	iam := file.Services[0]
	if names := []string{iam.Actions[0].Name, iam.Actions[1].Name, iam.Actions[2].Name}; strings.Join(names, ",") != "GetRole,ListRoles,PutRolePolicy" {
		t.Errorf("actions not sorted: %v", names)
	}
	if iam.Actions[2].Access != catalog.PermissionManagement || iam.Actions[1].Access != catalog.List || iam.Actions[0].Access != catalog.Read {
		t.Errorf("access levels wrong: %+v", iam.Actions)
	}

	first, err := encode(file)
	if err != nil {
		t.Fatal(err)
	}
	second, err := encode(file)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("encode is not deterministic")
	}
	c, err := catalog.Decode(bytes.NewReader(first))
	if err != nil {
		t.Fatalf("catalog cannot read the generated file: %v", err)
	}
	if _, ok := c.Lookup("iam:putrolepolicy"); !ok {
		t.Error("round trip lost an action")
	}
	zr, err := gzip.NewReader(bytes.NewReader(first))
	if err != nil {
		t.Fatal(err)
	}
	if !zr.ModTime.IsZero() || zr.Name != "" {
		t.Errorf("gzip header must not carry time or name: %v %q", zr.ModTime, zr.Name)
	}
}

func TestBuildRejects(t *testing.T) {
	tests := []struct {
		name     string
		services map[string]string
		urlFor   func(base, svc string) string
		want     string
	}{
		{
			"url on another host",
			map[string]string{"iam": iamDoc},
			func(_, svc string) string { return "https://evil.example/v1/" + svc + ".json" }, "outside",
		},
		{
			"plain http downgrade",
			map[string]string{"iam": iamDoc},
			func(base, svc string) string { return strings.Replace(sameHost(base, svc), "http://", "ftp://", 1) }, "outside",
		},
		{"document for another service", map[string]string{"iam": s3Doc}, sameHost, `document is for "s3"`},
		{"bad action name", map[string]string{"iam": `{"Name":"iam","Actions":[{"Name":"Put Role"}]}`}, sameHost, "invalid action name"},
		{"duplicate action", map[string]string{"iam": `{"Name":"iam","Actions":[{"Name":"A"},{"Name":"a"}]}`}, sameHost, "listed twice"},
		{"invalid json", map[string]string{"iam": `{`}, sameHost, "unexpected end"},
		{"bad prefix", map[string]string{"IAM!": iamDoc}, sameHost, "invalid service prefix"},
		{"missing document", map[string]string{"iam": iamDoc}, func(base, _ string) string { return base + "/v1/missing.json" }, "404"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeReference(t, tc.services, tc.urlFor)
			_, err := build(context.Background(), srv.Client(), srv.URL+"/", "2026-10-23", 2)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("build() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBuildRejectsEmptyAndOversizedIndex(t *testing.T) {
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "[]") }))
	defer empty.Close()
	if _, err := build(context.Background(), empty.Client(), empty.URL+"/", "d", 1); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty index: %v", err)
	}
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte(" "), maxIndexBytes+10))
	}))
	defer huge.Close()
	if _, err := build(context.Background(), huge.Client(), huge.URL+"/", "d", 1); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized index: %v", err)
	}
}

func TestCheckIndexURL(t *testing.T) {
	if err := checkIndexURL(defaultIndex, referenceHost); err != nil {
		t.Errorf("default index rejected: %v", err)
	}
	for _, bad := range []string{"http://servicereference.us-east-1.amazonaws.com/", "https://evil.example/", "::"} {
		if err := checkIndexURL(bad, referenceHost); err == nil {
			t.Errorf("checkIndexURL(%q) accepted", bad)
		}
	}
}

func TestRunWritesFile(t *testing.T) {
	srv := fakeReference(t, map[string]string{"iam": iamDoc}, sameHost)
	out := filepath.Join(t.TempDir(), "catalog.json.gz")
	if err := run(context.Background(), srv.Client(), srv.URL+"/", out, "2026-10-23", 1); err != nil {
		t.Fatalf("run() error = %v", err)
	}
}
