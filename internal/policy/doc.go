// Package policy parses IAM JSON policy documents into a typed model.
//
// Policy grammar is polymorphic: Action may be a string or a list, Principal
// may be "*" or a map of lists, Condition values may be strings, booleans,
// numbers or lists of them. This package turns every shape into one
// representation and rejects documents that AWS itself would not accept or
// that are ambiguous (duplicate keys, unknown elements, wrong types).
//
// Element names are matched exactly. encoding/json matches struct fields
// case-insensitively and keeps the last of duplicate keys; both behaviors
// would let a crafted document mean one thing to escalint and another to
// AWS, so this package checks the raw token stream first (see structure.go).
package policy
