package main

import (
	"fmt"
	"strings"
)

// Param is function parameter
type Param struct {
	Name      string
	Type      string
	fn        *Fn
	tmpVarIdx int
}

// extractParams parses s to extract function parameters.
func extractParams(s string, f *Fn) ([]*Param, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	allparams := strings.Split(s, ",")
	retlist := make([]*Param, len(allparams))
	for i, eachparam := range allparams {
		param := strings.TrimSpace(eachparam)
		paramtypepair := strings.Split(param, " ") //split on space
		if len(paramtypepair) != 2 {               //whoopsie, either too many spaces, or not enough!
			paramtypepair = strings.Split(param, "\t") //hmmm maybe it's a tab?
			if len(paramtypepair) != 2 {               //nope, abort
				return nil, fmt.Errorf("Could not extract function parameter (check for weird spaces) from %s", param)
			}
		}
		retlist[i] = &Param{
			Name:      strings.TrimSpace(paramtypepair[0]), //var name
			Type:      strings.TrimSpace(paramtypepair[1]), //var type
			fn:        f,
			tmpVarIdx: -1, //who knows
		}
	}
	return retlist, nil
}

// IsError determines if p parameter is used to return error.
func (p *Param) IsError() bool {
	return p.Name == "err" && p.Type == "error" //todo: relax requirement to name this param err
}

// join concatenates parameters ps into a string with sep separator.
// Each parameter is converted into string by applying fn to it
// before conversion.
func join(ps []*Param, fn func(*Param) string, sep string) string {
	if len(ps) == 0 {
		return ""
	}
	a := make([]string, 0)
	for _, p := range ps {
		a = append(a, fn(p))
	}
	return strings.Join(a, sep)
}

// HelperType returns type of parameter p used in helper function.
func (p *Param) HelperType() string {
	if p.Type == "string" {
		return p.fn.StrconvType()
	}
	return p.Type
}
