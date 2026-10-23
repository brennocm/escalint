// Package arn splits Amazon Resource Names into their six segments.
//
// Format: arn:partition:service:region:account-id:resource. The resource
// segment may itself contain colons and slashes, so only the first five
// separators are significant.
package arn

import (
	"fmt"
	"strings"
)

// ARN is a parsed Amazon Resource Name.
type ARN struct {
	Partition string
	Service   string
	Region    string
	Account   string
	Resource  string
}

// Parse splits s into its segments. It checks the shape only; it does not
// know which services or partitions exist.
func Parse(s string) (ARN, error) {
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return ARN{}, fmt.Errorf("arn: %q does not have the form arn:partition:service:region:account:resource", s)
	}
	a := ARN{Partition: parts[1], Service: parts[2], Region: parts[3], Account: parts[4], Resource: parts[5]}
	if a.Partition == "" || a.Service == "" || a.Resource == "" {
		return ARN{}, fmt.Errorf("arn: %q has an empty partition, service or resource", s)
	}
	return a, nil
}

func (a ARN) String() string {
	return strings.Join([]string{"arn", a.Partition, a.Service, a.Region, a.Account, a.Resource}, ":")
}

// IsAccountID reports whether s is a 12-digit AWS account ID.
func IsAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
