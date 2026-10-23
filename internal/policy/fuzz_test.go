package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// FuzzParsePolicy checks that Parse never panics, that it is deterministic
// and that every accepted document satisfies the model invariants.
func FuzzParsePolicy(f *testing.F) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join("testdata", e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data, uint8(KindIdentity))
		f.Add(data, uint8(KindResource))
	}
	f.Add([]byte(`{"Statement":{"Effect":"Deny","NotPrincipal":"*","Action":"*"}}`), uint8(KindResource))
	f.Add([]byte(`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"k":[true,1,"x"]}}}}`), uint8(KindSCP))

	f.Fuzz(func(t *testing.T, data []byte, kindByte uint8) {
		kind := Kind(kindByte % 4)
		doc, err := Parse(data, kind, Limits{})
		again, err2 := Parse(data, kind, Limits{})
		if (err == nil) != (err2 == nil) || !reflect.DeepEqual(doc, again) {
			t.Fatalf("Parse is not deterministic")
		}
		if err != nil {
			return
		}
		for i, st := range doc.Statements {
			if st.Index != i {
				t.Fatalf("statement %d has Index %d", i, st.Index)
			}
			if st.Effect != Allow && st.Effect != Deny {
				t.Fatalf("invalid effect %q accepted", st.Effect)
			}
			if (st.Action == nil) == (st.NotAction == nil) {
				t.Fatalf("statement %d must have exactly one of Action/NotAction", i)
			}
			if st.NotPrincipal != nil && st.Effect != Deny {
				t.Fatalf("NotPrincipal accepted with %s", st.Effect)
			}
			if kind == KindIdentity && (st.Principal != nil || st.NotPrincipal != nil) {
				t.Fatalf("identity policy with a principal accepted")
			}
		}
	})
}
