// Package jsonx validates the structure of untrusted JSON before it is
// decoded: well-formedness, bounded nesting and no duplicate keys.
//
// encoding/json silently keeps the last of duplicate keys, so a document
// with two "Effect" keys could mean one thing to escalint and another to
// AWS. Rejecting duplicates removes that ambiguity.
package jsonx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// ErrTooDeep is wrapped by errors for nesting beyond the allowed depth.
var ErrTooDeep = errors.New("nesting too deep")

// Error locates a structural problem. Path uses dots for keys and [i] for
// array items, for example "Statement[1].Condition.Bool".
type Error struct {
	Path string
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e.Path == "" {
		return e.Msg
	}
	return e.Path + ": " + e.Msg
}

func (e *Error) Unwrap() error {
	return e.Err
}

func errorf(path, format string, args ...any) *Error {
	return &Error{Path: path, Msg: fmt.Sprintf(format, args...)}
}

// Check walks the raw JSON tokens once. It rejects invalid JSON, trailing
// data, nesting deeper than maxDepth and duplicate keys in any object.
//
// The recursion depth is bounded by maxDepth, so hostile input cannot
// exhaust the stack.
func Check(data []byte, maxDepth int) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkValue(dec, "", 0, maxDepth); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errorf("", "unexpected data after the JSON document")
	}
	return nil
}

func walkValue(dec *json.Decoder, path string, depth, maxDepth int) error {
	tok, err := dec.Token()
	if err != nil {
		return &Error{Path: path, Msg: "invalid JSON", Err: err}
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	if depth >= maxDepth {
		return &Error{
			Path: path,
			Msg:  fmt.Sprintf("nesting deeper than %d levels", maxDepth),
			Err:  ErrTooDeep,
		}
	}

	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return &Error{Path: path, Msg: "invalid JSON", Err: err}
			}
			key, ok := keyTok.(string)
			if !ok {
				return errorf(path, "object key is not a string")
			}
			keyPath := JoinPath(path, key)
			if seen[key] {
				return errorf(keyPath, "duplicate key %s", strconv.Quote(key))
			}
			seen[key] = true
			if err := walkValue(dec, keyPath, depth+1, maxDepth); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := walkValue(dec, fmt.Sprintf("%s[%d]", path, i), depth+1, maxDepth); err != nil {
				return err
			}
		}
	default:
		return errorf(path, "unexpected %q", delim)
	}

	// Consume the closing delimiter.
	if _, err := dec.Token(); err != nil {
		return &Error{Path: path, Msg: "invalid JSON", Err: err}
	}
	return nil
}

// JoinPath appends an object key to a path. Keys come from untrusted
// documents and paths end up in terminal output, so a key with anything but
// printable ASCII (or with characters that would make the path ambiguous) is
// written as ["..."] with non-ASCII and control characters escaped. That
// keeps ANSI escape sequences and bidirectional overrides out of messages.
func JoinPath(parent, key string) string {
	if !plainKey(key) {
		return parent + "[" + strconv.QuoteToASCII(key) + "]"
	}
	if parent == "" {
		return key
	}
	return parent + "." + key
}

func plainKey(key string) bool {
	if key == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c <= ' ' || c >= 0x7f || c == '"' || c == '[' || c == ']' {
			return false
		}
	}
	return true
}
