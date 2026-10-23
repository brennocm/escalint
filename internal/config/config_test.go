package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const valid = `version: 1
trusted_accounts: ["222222222222"]
third_party_accounts: ["999999999999"]
suppressions:
  - rule: EL-TR-004
    arn: "arn:aws:iam::111111111111:role/legacy-*"
    reason: "Partner integration, reviewed 2026-09 (TICKET-12)"
    expires: 2027-01-31
  - rule: "EL-PE-0??"
    arn: "*"
    reason: ""
groupings:
  - name: payments
    arns: ["arn:aws:iam::*:role/payments-*"]
rules:
  disable: [EL-PE-014]
  experimental: true
fail_on: critical
min_severity: low
`

func TestDecodeValid(t *testing.T) {
	f, err := Decode(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || len(f.Suppressions) != 2 || f.Suppressions[0].Expires != "2027-01-31" || !f.Rules.Experimental || f.FailOn != "critical" {
		t.Errorf("decoded = %+v", f)
	}
	rc := f.RulesConfig()
	if rc.TrustedAccounts[0] != "222222222222" || rc.ThirdPartyAccounts[0] != "999999999999" {
		t.Errorf("rules config = %+v", rc)
	}
	var nilFile *File
	if len(nilFile.RulesConfig().TrustedAccounts) != 0 {
		t.Error("nil file config")
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":      "version: 1\ntrusted_acounts: []\n",
		"no version":       "trusted_accounts: []\n",
		"bad account":      "version: 1\ntrusted_accounts: [\"12345\"]\n",
		"bad rule":         "version: 1\nsuppressions:\n  - {rule: \"rm -rf\", arn: \"*\", reason: x}\n",
		"no arn":           "version: 1\nsuppressions:\n  - {rule: EL-PE-001, reason: x}\n",
		"bad date":         "version: 1\nsuppressions:\n  - {rule: EL-PE-001, arn: \"*\", reason: x, expires: tomorrow}\n",
		"bad grouping":     "version: 1\ngroupings:\n  - {name: x}\n",
		"bad severity":     "version: 1\nfail_on: urgent\n",
		"bad min severity": "version: 1\nmin_severity: none\n",
		"alias bomb":       "version: 1\na: &a [x, x]\nb: [*a, *a]\n",
		"anchor":           "version: 1\ntrusted_accounts: &x [\"222222222222\"]\n",
		"not yaml":         "version: [1\n",
		"too large":        "version: 1\n#" + strings.Repeat("x", MaxSize),
	}
	for name, src := range cases {
		if _, err := Decode(strings.NewReader(src)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := Decode(strings.NewReader("version: 1\nfail_on: none\n")); err != nil {
		t.Errorf("fail_on none: %v", err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, DefaultName)
	if err := os.WriteFile(p, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(p)
	if err != nil || f.Source != p {
		t.Fatalf("Load = %+v, %v", f, err)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	if err := os.WriteFile(p, []byte("version: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), p) {
		t.Errorf("error should name the file: %v", err)
	}
}

func TestExpired(t *testing.T) {
	s := Suppression{Expires: "2027-01-31"}
	if s.Expired(time.Date(2027, 1, 31, 23, 0, 0, 0, time.UTC)) {
		t.Error("expiry day is still valid")
	}
	if !s.Expired(time.Date(2027, 2, 1, 0, 0, 1, 0, time.UTC)) {
		t.Error("the day after is expired")
	}
	if (Suppression{}).Expired(time.Now()) {
		t.Error("no expiry never expires")
	}
	if !(Suppression{Expires: "garbage"}).Expired(time.Now()) {
		t.Error("garbage date must not suppress")
	}
}
