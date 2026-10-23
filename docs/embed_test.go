package docs

import "testing"

func TestRule(t *testing.T) {
	if doc, ok := Rule("EL-PE-022"); !ok || len(doc) < 100 {
		t.Fatalf("EL-PE-022 doc missing")
	}
	for _, bad := range []string{"../embed", "EL-PE-999", "rules/EL-PE-022", "EL-PE-022.md"} {
		if _, ok := Rule(bad); ok {
			t.Errorf("Rule(%q) returned a document", bad)
		}
	}
}
