// Package web exposes the compiled frontend (web/dist) to the Go binary.
//
// The embed directive lives in this directory, next to dist/, because
// //go:embed cannot reference parent directories. Building with -tags noui
// swaps the real frontend for a stub page so `go build` and `go test` work
// without Node.js (ADR 0002).
package web
