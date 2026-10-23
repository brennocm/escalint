package engine

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/brennocm/escalint/internal/snapshot"
	"github.com/brennocm/escalint/internal/synth"
)

func BenchmarkRun(b *testing.B) {
	for _, n := range benchSizes {
		gen, err := synth.Generate(synth.Options{Principals: n, Seed: 1, Accounts: 2})
		if err != nil {
			b.Fatal(err)
		}
		snap, err := snapshot.Load(bytes.NewReader(gen.JSON), snapshot.Options{})
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("principals=%d", n*2), func(b *testing.B) {
			for b.Loop() {
				if _, err := Run(snap, Options{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

var benchSizes = []int{1000, 10000}
