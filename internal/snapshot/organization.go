package snapshot

import (
	"fmt"
	"sort"

	"github.com/brennocm/escalint/internal/policy"
)

// NodeType is the kind of an entity in the organization tree.
type NodeType string

// Organization node types, as returned by AWS Organizations.
const (
	NodeRoot    NodeType = "ROOT"
	NodeOU      NodeType = "ORGANIZATIONAL_UNIT"
	NodeAccount NodeType = "ACCOUNT"
)

// PolicyType distinguishes SCPs from RCPs.
type PolicyType string

// Organization policy types, as returned by AWS Organizations.
const (
	PolicySCP PolicyType = "SERVICE_CONTROL_POLICY"
	PolicyRCP PolicyType = "RESOURCE_CONTROL_POLICY"
)

// OrgNode is a root, OU or account and its parent (empty for the root).
type OrgNode struct {
	ID     string
	Type   NodeType
	Parent string
}

// OrgPolicy is an SCP or RCP and the tree entities it is attached to.
type OrgPolicy struct {
	ID       string
	Type     PolicyType
	Name     string
	Document *policy.Document // nil when unparsable
	Targets  []string         // node IDs, sorted
}

// Organization is the optional AWS Organizations context of a snapshot.
type Organization struct {
	ID                  string
	ManagementAccountID string
	Nodes               []OrgNode   // sorted by ID
	Policies            []OrgPolicy // sorted by ID

	nodeByID map[string]OrgNode
}

// PathTo returns the IDs from the root down to the account (inclusive).
// SCPs and RCPs must allow at every level of this path.
func (o *Organization) PathTo(accountID string) ([]string, error) {
	node, ok := o.nodeByID[accountID]
	if !ok || node.Type != NodeAccount {
		return nil, fmt.Errorf("account %s is not in the organization tree", accountID)
	}
	var path []string
	for id := accountID; id != ""; id = o.nodeByID[id].Parent {
		path = append(path, id)
		if len(path) > len(o.nodeByID) {
			return nil, fmt.Errorf("cycle in organization tree above %s", accountID)
		}
	}
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path, nil
}

// PoliciesAttachedTo returns the policies of the given type attached
// directly to node, sorted by ID.
func (o *Organization) PoliciesAttachedTo(nodeID string, t PolicyType) []*OrgPolicy {
	var out []*OrgPolicy
	for i := range o.Policies {
		p := &o.Policies[i]
		if p.Type != t {
			continue
		}
		for _, target := range p.Targets {
			if target == nodeID {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// buildOrganization validates the tree: one root, known node types, parents
// that exist, no cycles, and policy targets that exist.
func buildOrganization(w *wireOrganization, limits policy.Limits) (*Organization, []Diagnostic, error) {
	org := &Organization{ID: w.ID, ManagementAccountID: w.ManagementAccountID, nodeByID: map[string]OrgNode{}}
	roots := 0
	for _, n := range w.Tree {
		node := OrgNode{ID: n.ID, Type: NodeType(n.Type)}
		if n.Parent != nil {
			node.Parent = *n.Parent
		}
		switch node.Type {
		case NodeRoot:
			roots++
			if node.Parent != "" {
				return nil, nil, fmt.Errorf("organization root %s cannot have a parent", node.ID)
			}
		case NodeOU, NodeAccount:
			if node.Parent == "" {
				return nil, nil, fmt.Errorf("organization node %s has no parent", node.ID)
			}
		default:
			return nil, nil, fmt.Errorf("organization node %s has unknown type %q", node.ID, n.Type)
		}
		if node.ID == "" {
			return nil, nil, fmt.Errorf("organization node with empty id")
		}
		if _, dup := org.nodeByID[node.ID]; dup {
			return nil, nil, fmt.Errorf("organization node %s appears twice", node.ID)
		}
		org.nodeByID[node.ID] = node
		org.Nodes = append(org.Nodes, node)
	}
	if roots != 1 {
		return nil, nil, fmt.Errorf("organization tree must have exactly one root, found %d", roots)
	}
	for _, node := range org.Nodes {
		if node.Parent != "" {
			if _, ok := org.nodeByID[node.Parent]; !ok {
				return nil, nil, fmt.Errorf("organization node %s has unknown parent %s", node.ID, node.Parent)
			}
		}
		if node.Type == NodeAccount {
			if _, err := org.PathTo(node.ID); err != nil {
				return nil, nil, err
			}
		}
	}
	sort.Slice(org.Nodes, func(i, j int) bool { return org.Nodes[i].ID < org.Nodes[j].ID })

	var diags []Diagnostic
	for _, p := range w.Policies {
		op := OrgPolicy{ID: p.ID, Type: PolicyType(p.Type), Name: p.Name, Targets: append([]string(nil), p.Targets...)}
		kind := policy.KindSCP
		switch op.Type {
		case PolicySCP:
		case PolicyRCP:
			kind = policy.KindRCP
		default:
			return nil, nil, fmt.Errorf("organization policy %s has unknown type %q", p.ID, p.Type)
		}
		for _, target := range op.Targets {
			if _, ok := org.nodeByID[target]; !ok {
				return nil, nil, fmt.Errorf("organization policy %s targets unknown node %s", p.ID, target)
			}
		}
		sort.Strings(op.Targets)
		doc, diag := parseDocument(p.Document, kind, limits)
		op.Document = doc
		if diag != nil {
			diag.Entity = p.ID
			diag.Policy = p.Name
			diags = append(diags, *diag)
		}
		org.Policies = append(org.Policies, op)
	}
	sort.Slice(org.Policies, func(i, j int) bool { return org.Policies[i].ID < org.Policies[j].ID })
	return org, diags, nil
}
