package rules

import "sort"

// All returns every rule, sorted by ID. Adding a rule means adding its
// constructor here (and its docs/rules/<ID>.md); there is no registration
// by side effect.
func All() []Rule {
	list := []Rule{
		elPE001(),
		elPE002(),
		elPE003(),
		elPE004(),
		elPE005(),
		elPE006(),
		elPE007(),
		elPE008(),
		elPE009(),
		elPE010(),
		elPE011(),
		elPE012(),
		elPE013(),
		elPE014(),
		elPE015(),
		elPE016(),
		elPE017(),
		elPE018(),
		elPE019(),
		elPE020(),
		elPE021(),
		elPE022(),
		elPE023(),
		elPE024(),
		elPE025(),
		elPE026(),
		elPE027(),
		elPE028(),
		elPE029(),
		elPE030(),
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Meta().ID < list[j].Meta().ID })
	return list
}

// ByID returns the rule with the given ID.
func ByID(id string) (Rule, bool) {
	for _, r := range All() {
		if r.Meta().ID == id {
			return r, true
		}
	}
	return nil, false
}
