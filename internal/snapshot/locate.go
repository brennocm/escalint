package snapshot

import (
	"bytes"
	"encoding/json/jsontext"
	"sort"
	"strconv"
	"strings"
)

// Locator maps policy references back to lines of the raw snapshot file,
// for SARIF physical locations (ADR 0011). It indexes JSON pointers of the
// values it walks with jsontext.Decoder and its InputOffset.
type Locator struct {
	starts    map[string]int64  // JSON pointer -> byte offset of the value
	arnAt     map[string]string // ARN -> pointer of the object holding it
	nameAt    map[string]string // pointer of an inline policy object -> PolicyName
	isDefault map[string]bool   // pointer of a default policy version
	newlines  []int64
}

// Locate indexes a snapshot file. It fails only on malformed JSON, which
// Load would have rejected first.
func Locate(data []byte) (*Locator, error) {
	l := &Locator{
		starts: map[string]int64{}, arnAt: map[string]string{},
		nameAt: map[string]string{}, isDefault: map[string]bool{},
	}
	for i, c := range data {
		if c == '\n' {
			l.newlines = append(l.newlines, int64(i))
		}
	}
	dec := jsontext.NewDecoder(bytes.NewReader(data), jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	for {
		before := dec.InputOffset()
		tok, err := dec.ReadToken()
		if err != nil {
			if dec.StackDepth() == 0 && before > 0 {
				break // end of input after the top-level value
			}
			return nil, err
		}
		kind, n := dec.StackIndex(dec.StackDepth())
		if tok.Kind() == '"' && kind == '{' && n%2 == 1 {
			continue // an object name, not a value
		}
		if tok.Kind() == '}' || tok.Kind() == ']' {
			continue
		}
		ptr := string(dec.StackPointer())
		parent, key := splitPointer(ptr)
		// Only containers and policy documents kept as strings are looked
		// up by Find; skipping other scalars keeps the index small.
		if tok.Kind() == '{' || tok.Kind() == '[' || tok.Kind() == '"' && documentKeys[key] {
			l.starts[ptr] = skipSeparators(data, before)
		}
		switch {
		case tok.Kind() == '"' && (key == "Arn" || key == "arn"):
			if _, dup := l.arnAt[tok.String()]; !dup {
				l.arnAt[tok.String()] = parent
			}
		case tok.Kind() == '"' && key == "PolicyName":
			l.nameAt[parent] = tok.String()
		case tok.Kind() == 't' && key == "IsDefaultVersion":
			l.isDefault[parent] = true
		}
		if dec.StackDepth() == 0 {
			break
		}
	}
	return l, nil
}

// documentKeys name the members that hold policy documents, which the SDK
// returns as URL-encoded strings.
var documentKeys = map[string]bool{"PolicyDocument": true, "Document": true, "AssumeRolePolicyDocument": true, "document": true}

// skipSeparators moves from the end of the previous token to the start of
// the next value.
func skipSeparators(data []byte, off int64) int64 {
	for off < int64(len(data)) {
		switch data[off] {
		case ' ', '\t', '\n', '\r', ':', ',':
			off++
		default:
			return off
		}
	}
	return off
}

func splitPointer(p string) (parent, last string) {
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return "", p
	}
	return p[:i], p[i+1:]
}

// Line returns the 1-based line of a byte offset.
func (l *Locator) Line(off int64) int {
	return sort.Search(len(l.newlines), func(i int) bool { return l.newlines[i] >= off }) + 1
}

// Find returns the line of the statement behind a location: the policy
// source format of evidence ("inline:<owner>/<name>", "trust:<arn>",
// "rewritten-trust:<arn>", a managed policy ARN) or of diagnostics (an
// inline policy name of entity, or a managed policy ARN). It falls back to
// the policy document, then the entity object; ok is false when nothing
// matched.
func (l *Locator) Find(entity, policy string, statement int) (line int, ok bool) {
	if doc := l.document(entity, policy); doc != "" {
		if statement >= 0 {
			for _, p := range []string{doc + "/Statement/" + strconv.Itoa(statement), doc + "/Statement"} {
				if off, found := l.starts[p]; found {
					return l.Line(off), true
				}
			}
		}
		if off, found := l.starts[doc]; found {
			return l.Line(off), true
		}
	}
	for _, arn := range []string{entity, trimPolicyPrefix(policy)} {
		if p, found := l.arnAt[arn]; found {
			return l.Line(l.starts[p]), true
		}
	}
	return 1, false
}

func trimPolicyPrefix(policy string) string {
	for _, prefix := range []string{"trust:", "rewritten-trust:"} {
		if arn, ok := strings.CutPrefix(policy, prefix); ok {
			return arn
		}
	}
	if rest, ok := strings.CutPrefix(policy, "inline:"); ok {
		if i := strings.LastIndexByte(rest, '/'); i >= 0 {
			return rest[:i]
		}
	}
	return policy
}

// document returns the JSON pointer of the policy document, or "".
func (l *Locator) document(entity, policy string) string {
	for _, prefix := range []string{"trust:", "rewritten-trust:"} {
		if arn, ok := strings.CutPrefix(policy, prefix); ok {
			if p, found := l.arnAt[arn]; found {
				return p + "/AssumeRolePolicyDocument"
			}
			return ""
		}
	}
	owner, name := entity, policy
	if rest, ok := strings.CutPrefix(policy, "inline:"); ok {
		i := strings.LastIndexByte(rest, '/')
		if i < 0 {
			return ""
		}
		owner, name = rest[:i], rest[i+1:]
	} else if strings.HasPrefix(policy, "arn:") {
		mp, found := l.arnAt[policy]
		if !found {
			return ""
		}
		for i := 0; ; i++ {
			v := mp + "/PolicyVersionList/" + strconv.Itoa(i)
			if _, exists := l.starts[v]; !exists {
				return ""
			}
			if l.isDefault[v] {
				return v + "/Document"
			}
		}
	}
	op, found := l.arnAt[owner]
	if !found {
		return ""
	}
	for _, list := range []string{"UserPolicyList", "RolePolicyList", "GroupPolicyList"} {
		for i := 0; ; i++ {
			p := op + "/" + list + "/" + strconv.Itoa(i)
			if _, exists := l.starts[p]; !exists {
				break
			}
			if l.nameAt[p] == name {
				return p + "/PolicyDocument"
			}
		}
	}
	return ""
}
