package policy

// Limits bounds the work spent on one document. Real IAM policies are small
// (managed policies are at most 6,144 characters), so the defaults are
// generous while still stopping hostile input early.
type Limits struct {
	MaxBytes      int // raw document size
	MaxDepth      int // nesting of objects and arrays
	MaxStatements int
	MaxValues     int // total strings across all elements of one document
}

// DefaultLimits are used when a caller passes the zero Limits value.
var DefaultLimits = Limits{
	MaxBytes:      128 << 10,
	MaxDepth:      16,
	MaxStatements: 1000,
	MaxValues:     20000,
}

func (l Limits) withDefaults() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultLimits.MaxBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultLimits.MaxDepth
	}
	if l.MaxStatements <= 0 {
		l.MaxStatements = DefaultLimits.MaxStatements
	}
	if l.MaxValues <= 0 {
		l.MaxValues = DefaultLimits.MaxValues
	}
	return l
}
