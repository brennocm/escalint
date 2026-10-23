package policy

import (
	"errors"
	"fmt"
)

// ErrLimitExceeded is wrapped by errors caused by a configured size limit.
var ErrLimitExceeded = errors.New("limit exceeded")

// ParseError reports why a document could not be parsed. Path locates the
// problem inside the document, for example "Statement[1].Principal.AWS".
type ParseError struct {
	Path string
	Msg  string
	Err  error
}

func (e *ParseError) Error() string {
	if e.Path == "" {
		return "policy: " + e.Msg
	}
	return fmt.Sprintf("policy: %s: %s", e.Path, e.Msg)
}

func (e *ParseError) Unwrap() error {
	return e.Err
}

func errorf(path, format string, args ...any) *ParseError {
	return &ParseError{Path: path, Msg: fmt.Sprintf(format, args...)}
}
