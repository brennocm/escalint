package policy

import "encoding/json"

// Canonical JSON of a parsed document, for display (the web UI's policy
// explainer). Element order is fixed and statements keep their order, so
// statement indices match the evidence. Values keep their spelling.

type canonicalDoc struct {
	Version   string               `json:"Version,omitempty"`
	ID        string               `json:"Id,omitempty"`
	Statement []canonicalStatement `json:"Statement"`
}

type canonicalStatement struct {
	Sid          string                         `json:"Sid,omitempty"`
	Effect       Effect                         `json:"Effect"`
	Principal    any                            `json:"Principal,omitempty"`
	NotPrincipal any                            `json:"NotPrincipal,omitempty"`
	Action       []string                       `json:"Action,omitempty"`
	NotAction    []string                       `json:"NotAction,omitempty"`
	Resource     []string                       `json:"Resource,omitempty"`
	NotResource  []string                       `json:"NotResource,omitempty"`
	Condition    map[string]map[string][]string `json:"Condition,omitempty"`
}

func canonicalPrincipal(p *Principal) any {
	if p == nil {
		return nil
	}
	if p.Wildcard {
		return "*"
	}
	m := map[string][]string{}
	for k, v := range map[string]StringList{"AWS": p.AWS, "CanonicalUser": p.CanonicalUser, "Federated": p.Federated, "Service": p.Service} {
		if v != nil {
			m[k] = v
		}
	}
	return m
}

// CanonicalJSON returns the document as JSON with a fixed element order.
func (d *Document) CanonicalJSON() ([]byte, error) {
	out := canonicalDoc{Version: d.Version, ID: d.ID, Statement: []canonicalStatement{}}
	for i := range d.Statements {
		st := &d.Statements[i]
		cs := canonicalStatement{
			Sid: st.Sid, Effect: st.Effect,
			Principal: canonicalPrincipal(st.Principal), NotPrincipal: canonicalPrincipal(st.NotPrincipal),
			Action: st.Action, NotAction: st.NotAction, Resource: st.Resource, NotResource: st.NotResource,
		}
		if len(st.Condition) > 0 {
			cs.Condition = map[string]map[string][]string{}
			for _, c := range st.Condition {
				if cs.Condition[c.Operator] == nil {
					cs.Condition[c.Operator] = map[string][]string{}
				}
				cs.Condition[c.Operator][c.Key] = append(cs.Condition[c.Operator][c.Key], c.Values...)
			}
		}
		out.Statement = append(out.Statement, cs)
	}
	return json.Marshal(out)
}
