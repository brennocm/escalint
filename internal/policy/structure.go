package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// checkStructure walks the raw JSON tokens once before any decoding. It
// rejects invalid JSON, trailing data, nesting deeper than maxDepth and
// duplicate keys in any object, reporting the path of the problem.
//
// The recursion depth is bounded by maxDepth, so hostile input cannot
// exhaust the stack.
func checkStructure(data []byte, maxDepth int) error {
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
		return &ParseError{Path: path, Msg: "invalid JSON", Err: err}
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	if depth >= maxDepth {
		return &ParseError{
			Path: path,
			Msg:  fmt.Sprintf("nesting deeper than %d levels", maxDepth),
			Err:  ErrLimitExceeded,
		}
	}

	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return &ParseError{Path: path, Msg: "invalid JSON", Err: err}
			}
			key, ok := keyTok.(string)
			if !ok {
				return errorf(path, "object key is not a string")
			}
			keyPath := joinPath(path, key)
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
		return &ParseError{Path: path, Msg: "invalid JSON", Err: err}
	}
	return nil
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}
