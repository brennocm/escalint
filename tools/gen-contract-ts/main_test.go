package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// The committed TypeScript contract matches the schema.
func TestGeneratedContractUpToDate(t *testing.T) {
	raw, err := os.ReadFile("../../schema/analysis.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := generate(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../web/src/contract/analysis.ts")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("web/src/contract/analysis.ts is stale; run make gen-contract")
	}
	for _, s := range []string{"export interface Analysis {", "export type NodeId = string;", `readonly edge_kind: "assume"`, `| null;`, "export const SCHEMA_VERSION = \"1\";"} {
		if !strings.Contains(string(got), s) {
			t.Errorf("output lacks %q", s)
		}
	}
}

func TestRejectsUnsupportedSchemas(t *testing.T) {
	cases := map[string]string{
		"unknown keyword":   `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"string","maxLength":3}}}`,
		"open object":       `{"type":"object","properties":{"a":{"type":"string"}}}`,
		"external ref":      `{"type":"object","additionalProperties":false,"properties":{"a":{"$ref":"other.json"}}}`,
		"array no items":    `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"array"}}}`,
		"number map":        `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"object","additionalProperties":{"type":"number"}}}}`,
		"untyped":           `{"type":"object","additionalProperties":false,"properties":{"a":{}}}`,
		"bad type list":     `{"type":"object","additionalProperties":false,"properties":{"a":{"type":[1]}}}`,
		"unsupported type":  `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"tuple"}}}`,
		"map without value": `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"object"}}}`,
	}
	for name, s := range cases {
		if _, err := generate([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRunWritesFile(t *testing.T) {
	out := t.TempDir() + "/a.ts"
	if err := run("../../schema/analysis.v1.schema.json", out); err != nil {
		t.Fatal(err)
	}
	if err := run("missing.json", out); err == nil {
		t.Error("missing schema accepted")
	}
}
