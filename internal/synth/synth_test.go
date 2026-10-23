package synth

import (
	"bytes"
	"errors"
	"testing"

	"github.com/brennocm/escalint/internal/engine"
	"github.com/brennocm/escalint/internal/snapshot"
)

func TestDeterministic(t *testing.T) {
	a, err := Generate(Options{Principals: 40, Seed: 7, Accounts: 2})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(Options{Principals: 40, Seed: 7, Accounts: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.JSON, b.JSON) {
		t.Error("same seed, different output")
	}
	c, err := Generate(Options{Principals: 40, Seed: 8, Accounts: 2})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.JSON, c.JSON) {
		t.Error("different seeds, same output")
	}
}

func TestLoadsAndPlantsPaths(t *testing.T) {
	for _, random := range []bool{false, true} {
		res, err := Generate(Options{Principals: 60, Seed: 1, Accounts: 2, EscalationRate: 0.3, RandomNames: random})
		if err != nil {
			t.Fatal(err)
		}
		snap, err := snapshot.Load(bytes.NewReader(res.JSON), snapshot.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Diagnostics) != 0 {
			t.Errorf("diagnostics: %+v", snap.Diagnostics)
		}
		out, err := engine.Run(snap, engine.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Paths) == 0 {
			t.Error("no planted paths found")
		}
		if len(res.Identifiers) < 60 {
			t.Errorf("only %d identifiers", len(res.Identifiers))
		}
	}
	none, err := Generate(Options{Principals: 30, Seed: 1, NoEscalations: true})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := snapshot.Load(bytes.NewReader(none.JSON), snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := engine.Run(snap, engine.Options{}); err != nil || len(out.Paths) != 0 {
		t.Errorf("no-escalation snapshot has %d paths (%v)", len(out.Paths), err)
	}
}

func TestInvalidOptions(t *testing.T) {
	for _, o := range []Options{{Principals: 2}, {Accounts: 10}, {EscalationRate: 2}} {
		if _, err := Generate(o); !errors.Is(err, ErrOptions) {
			t.Errorf("%+v: err = %v", o, err)
		}
	}
}
