package attack

import "testing"

func TestDefault(t *testing.T) {
	d, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != "20.0" || len(d.Techniques) < 50 {
		t.Fatalf("version %q with %d techniques", d.Version, len(d.Techniques))
	}
	tech, ok := d.Lookup("T1098.003")
	if !ok || tech.Name != "Account Manipulation: Additional Cloud Roles" || tech.URL != "https://attack.mitre.org/techniques/T1098/003" {
		t.Errorf("T1098.003 = %+v", tech)
	}
	// Every technique the research mapped (docs/research.md §13) must exist.
	for _, id := range []string{"T1098.001", "T1098.003", "T1548.005", "T1078.004", "T1648", "T1651", "T1199"} {
		if _, ok := d.Lookup(id); !ok {
			t.Errorf("%s missing from the embedded data", id)
		}
	}
	if _, ok := d.Lookup("T1484.002"); ok {
		t.Error("T1484.002 has no IaaS platform and must not be embedded")
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := Decode([]byte("{")); err == nil {
		t.Error("invalid JSON accepted")
	}
	if _, err := Decode([]byte(`{"techniques":[{"id":"T1"},{"id":"T1"}]}`)); err == nil {
		t.Error("duplicate technique accepted")
	}
}
