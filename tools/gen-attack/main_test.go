package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const tinyBundle = `{"objects":[
 {"type":"x-mitre-collection","x_mitre_version":"20.0"},
 {"type":"x-mitre-tactic","x_mitre_shortname":"privilege-escalation","name":"Privilege Escalation"},
 {"type":"x-mitre-tactic","x_mitre_shortname":"persistence","name":"Persistence"},
 {"type":"attack-pattern","name":"Account Manipulation","x_mitre_platforms":["IaaS"],
  "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"persistence"}],
  "external_references":[{"source_name":"mitre-attack","external_id":"T1098","url":"https://attack.mitre.org/techniques/T1098"}]},
 {"type":"attack-pattern","name":"Additional Cloud Roles","x_mitre_platforms":["IaaS","SaaS"],
  "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"privilege-escalation"},{"kill_chain_name":"mitre-attack","phase_name":"persistence"}],
  "external_references":[{"source_name":"mitre-attack","external_id":"T1098.003","url":"https://attack.mitre.org/techniques/T1098/003"}]},
 {"type":"attack-pattern","name":"Windows only","x_mitre_platforms":["Windows"],
  "external_references":[{"source_name":"mitre-attack","external_id":"T9999"}]},
 {"type":"attack-pattern","name":"Old","revoked":true,"x_mitre_platforms":["IaaS"],
  "external_references":[{"source_name":"mitre-attack","external_id":"T8888"}]}
]}`

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestExtract(t *testing.T) {
	f, err := extract([]byte(tinyBundle), sha(tinyBundle))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Techniques) != 2 {
		t.Fatalf("techniques = %+v, want only the active IaaS ones", f.Techniques)
	}
	sub := f.Techniques[1]
	if sub.ID != "T1098.003" || sub.Name != "Account Manipulation: Additional Cloud Roles" ||
		strings.Join(sub.Tactics, ",") != "Persistence,Privilege Escalation" {
		t.Errorf("sub-technique = %+v", sub)
	}
}

func TestExtractRejects(t *testing.T) {
	if _, err := extract([]byte(tinyBundle), strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("hash mismatch: %v", err)
	}
	other := strings.Replace(tinyBundle, `"20.0"`, `"19.2"`, 1)
	if _, err := extract([]byte(other), sha(other)); err == nil || !strings.Contains(err.Error(), "expected 20.0") {
		t.Errorf("wrong release: %v", err)
	}
	if _, err := extract([]byte("{"), sha("{")); err == nil {
		t.Error("invalid JSON accepted")
	}
}

func TestRunWithLocalBundleRejectsUnpinnedContent(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(in, []byte(tinyBundle), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(in, filepath.Join(dir, "out.json")); err == nil {
		t.Error("a bundle that is not the pinned release must be rejected")
	}
}
