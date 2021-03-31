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

// tmpVar returns temp variable name that will be used to represent p during syscall.
func (p *Param) tmpVar() string {
	if p.tmpVarIdx < 0 {
		p.tmpVarIdx = p.fn.curTmpVarIdx
		p.fn.curTmpVarIdx++
	}
	return fmt.Sprintf("_p%d", p.tmpVarIdx)
}

// BoolTmpVarCode returns source code for bool temp variable.
func (p *Param) BoolTmpVarCode() string {
	const code = `var %s uint32
	if %s {
		%s = 1
	} else {
		%s = 0
	}`
	tmp := p.tmpVar()
	return fmt.Sprintf(code, tmp, p.Name, tmp, tmp)
}

// BoolPointerTmpVarCode returns source code for bool temp variable.
func (p *Param) BoolPointerTmpVarCode() string {
	const code = `var %s uint32
	if *%s {
		%s = 1
	} else {
		%s = 0
	}`
	tmp := p.tmpVar()
	return fmt.Sprintf(code, tmp, p.Name, tmp, tmp)
}

// SliceTmpVarCode returns source code for slice temp variable.
func (p *Param) SliceTmpVarCode() string {
	const code = `var %s *%s
	if len(%s) > 0 {
		%s = &%s[0]
	}`
	tmp := p.tmpVar()
	return fmt.Sprintf(code, tmp, p.Type[2:], p.Name, tmp, p.Name)
}

// StringTmpVarCode returns source code for string temp variable.
func (p *Param) StringTmpVarCode() string {
	errvar := p.fn.Rets.ErrorVarName()
	if errvar == "" {
		errvar = "_"
	}
	tmp := p.tmpVar()
	const code = `var %s %s
	%s, %s = %s(%s)`
	s := fmt.Sprintf(code, tmp, p.fn.StrconvType(), tmp, errvar, p.fn.StrconvFunc(), p.Name)
	if errvar == "-" {
		return s
	}
	const morecode = `
	if %s != nil {
		return
	}`
	return s + fmt.Sprintf(morecode, errvar)
}

// TmpVarCode returns source code for temp variable.
func (p *Param) TmpVarCode() string {
	switch {
	case p.Type == "bool":
		return p.BoolTmpVarCode()
	case p.Type == "*bool":
		return p.BoolPointerTmpVarCode()
	case strings.HasPrefix(p.Type, "[]"):
		return p.SliceTmpVarCode()
	default:
		return ""
	}
}

// SyscallArgList returns source code fragments representing p parameter
// in syscall. Slices are translated into 2 syscall parameters: pointer to
// the first element and length.
func (p *Param) SyscallArgList() []string {
	t := p.HelperType()
	var s string
	switch {
	case t == "*bool":
		s = fmt.Sprintf("unsafe.Pointer(&%s)", p.tmpVar())
	case t[0] == '*':
		s = fmt.Sprintf("unsafe.Pointer(%s)", p.Name)
	case t == "bool":
		s = p.tmpVar()
	case strings.HasPrefix(t, "[]"):
		return []string{
			fmt.Sprintf("uintptr(unsafe.Pointer(%s))", p.tmpVar()),
			fmt.Sprintf("uintptr(len(%s))", p.Name),
		}
	default:
		s = p.Name
	}
	return []string{fmt.Sprintf("uintptr(%s)", s)}
}

// TmpVarReadbackCode returns source code for reading back the temp variable into the original variable.
func (p *Param) TmpVarReadbackCode() string {
	switch {
	case p.Type == "*bool":
		return fmt.Sprintf("*%s = %s != 0", p.Name, p.tmpVar())
	default:
		return ""
	}
}
