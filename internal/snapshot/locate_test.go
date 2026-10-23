package snapshot

import (
	"os"
	"strings"
	"testing"
)

func lineOf(t *testing.T, data []byte, needle string, nth int) int {
	t.Helper()
	off := 0
	for range nth {
		i := strings.Index(string(data[off:]), needle)
		if i < 0 {
			t.Fatalf("%q not found", needle)
		}
		off += i + 1
	}
	return strings.Count(string(data[:off-1]), "\n") + 1
}

func TestLocate(t *testing.T) {
	data, err := os.ReadFile("testdata/envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	l, err := Locate(data)
	if err != nil {
		t.Fatal(err)
	}
	// Inline user policy: the statement is a single object.
	got, ok := l.Find("arn:aws:iam::111111111111:user/alice", "inline:arn:aws:iam::111111111111:user/alice/keys", 0)
	if want := lineOf(t, data, `"Statement"`, 1); !ok || got < want || got > want+1 {
		t.Errorf("inline statement line = %d (ok %v), want about %d", got, ok, want)
	}
	// Diagnostics refer to inline policies by name.
	if got2, ok := l.Find("arn:aws:iam::111111111111:user/alice", "keys", -1); !ok || got2 > got {
		t.Errorf("inline by name = %d %v", got2, ok)
	}
	if _, ok := l.Find("arn:aws:iam::111111111111:user/alice", "missing", 0); !ok {
		t.Error("entity fallback failed")
	}
	if line, ok := l.Find("arn:aws:iam::999999999999:user/nobody", "", 0); ok || line != 1 {
		t.Errorf("unknown entity = %d %v", line, ok)
	}
	if _, ok := l.Find("", "inline:nobody", 0); ok {
		t.Error("malformed inline source matched")
	}
	if _, ok := l.Find("", "trust:arn:aws:iam::999999999999:role/none", 0); ok {
		t.Error("unknown trust matched")
	}
	if _, ok := l.Find("", "arn:aws:iam::999999999999:policy/none", 0); ok {
		t.Error("unknown managed policy matched")
	}
}

func TestLocateTrustAndManaged(t *testing.T) {
	data, err := os.ReadFile("../rules/testdata/EL-PE-014/vulnerable/snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	l, err := Locate(data)
	if err != nil {
		t.Fatal(err)
	}
	trust, ok := l.Find("", "trust:arn:aws:iam::111111111111:role/target", 0)
	if !ok || trust <= lineOf(t, data, `"arn:aws:iam::111111111111:role/target"`, 1) {
		t.Errorf("trust line = %d %v", trust, ok)
	}
	managed, ok := l.Find("", "arn:aws:iam::111111111111:policy/S3Only", 0)
	if want := lineOf(t, data, `"Statement"`, 1) + 1; !ok || managed != want {
		t.Errorf("managed statement line = %d %v, want %d", managed, ok, want)
	}
	rewritten, ok := l.Find("", "rewritten-trust:arn:aws:iam::111111111111:role/target", 0)
	if !ok || rewritten != trust {
		t.Errorf("rewritten trust = %d", rewritten)
	}
	if _, err := Locate([]byte(`{"a": [1, 2`)); err == nil {
		t.Error("truncated JSON accepted")
	}
	if l2, err := Locate([]byte(`{"Arn":"x"}`)); err != nil || l2.Line(0) != 1 {
		t.Errorf("one-line document: %v", err)
	}
}
