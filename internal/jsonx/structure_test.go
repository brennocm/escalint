package jsonx

import (
	"errors"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	tests := []struct {
		name     string
		doc      string
		depth    int
		wantPath string
		wantMsg  string // empty means valid
	}{
		{"scalar", `"x"`, 4, "", ""},
		{"nested ok", `{"a":[{"b":[1,2]},{"b":null}]}`, 4, "", ""},
		{"same key in sibling objects", `[{"k":1},{"k":2}]`, 4, "", ""},
		{"duplicate at root", `{"a":1,"a":2}`, 4, "a", `duplicate key "a"`},
		{"duplicate inside array item", `{"x":[{"k":1},{"k":1,"k":2}]}`, 4, "x[1].k", "duplicate key"},
		{"too deep", `[[[[1]]]]`, 3, "[0][0][0]", "nesting deeper than 3"},
		{"invalid", `{"a":}`, 4, "a", "invalid JSON"},
		{"trailing", `{} []`, 4, "", "unexpected data"},
		{"empty", ``, 4, "", "invalid JSON"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Check([]byte(tc.doc), tc.depth)
			if tc.wantMsg == "" {
				if err != nil {
					t.Fatalf("Check() error = %v, want nil", err)
				}
				return
			}
			var je *Error
			if !errors.As(err, &je) {
				t.Fatalf("Check() error = %v, want *Error", err)
			}
			if je.Path != tc.wantPath || !strings.Contains(je.Error(), tc.wantMsg) {
				t.Errorf("got path %q error %q, want path %q containing %q", je.Path, je.Error(), tc.wantPath, tc.wantMsg)
			}
		})
	}
}

func TestCheckTooDeepIsDetectable(t *testing.T) {
	if err := Check([]byte(`[[1]]`), 1); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("Check() error = %v, want ErrTooDeep", err)
	}
}

func TestJoinPath(t *testing.T) {
	if got := JoinPath("", "a"); got != "a" {
		t.Errorf("JoinPath(\"\", a) = %q", got)
	}
	if got := JoinPath("a[0]", "b"); got != "a[0].b" {
		t.Errorf("JoinPath = %q", got)
	}
}

func FuzzCheck(f *testing.F) {
	f.Add([]byte(`{"a":[1,{"b":2}]}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic or hang, and must be deterministic.
		first, second := Check(data, 16), Check(data, 16)
		if (first == nil) != (second == nil) {
			t.Fatalf("Check is not deterministic: %v vs %v", first, second)
		}
	})
}
