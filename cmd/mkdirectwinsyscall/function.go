package main

import (
	"errors"
	"fmt"
	"strings"
)

// Fn describes syscall function.
type Fn struct {
	Name        string
	Params      []*Param
	Rets        *Rets
	PrintTrace  bool
	dllname     string
	dllfuncname string
	src         string
	// TODO: get rid of this field and just use parameter index instead
	curTmpVarIdx int    // insure tmp variables have uniq names
	mode         string //bananananamode
	Propermode   string
	Global       bool
	Internal     bool //is the function internal?
}

// extractSection extracts text out of string s starting after start
// and ending just before end. found return value will indicate success,
// and prefix, body and suffix will contain correspondent parts of string s.
func extractSection(s string, start, end rune) (prefix, body, suffix string, found bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, string(start)) {
		// no prefix
		body = s[1:]
	} else {
		a := strings.SplitN(s, string(start), 2)
		if len(a) != 2 {
			suffix = s
			found = false
			return
		}
		prefix = a[0]
		body = a[1]
	}
	a := strings.SplitN(body, string(end), 2)
	if len(a) != 2 {
		//has no end marker. suffix won't be set, but body/prefix may be
		found = false
		return
	}
	return prefix, a[0], a[1], true
}

//NewFn parses string s and return created function Fn.
func NewFn(s, mode string, global, internal bool) (*Fn, error) {
	s = strings.TrimSpace(s) //pesky spaces

	f := &Fn{
		Rets:       &Rets{}, //todo:
		src:        s,
		PrintTrace: *printTraceFlag,
		Internal:   internal,
		Propermode: mode,
		Global:     global,
	}
	// function name and args (get everything between first set of brackets)
	prefix, body, s, found := extractSection(s, '(', ')')
	if !found || prefix == "" {
		return nil, fmt.Errorf("Could not extract function name and parameters from %s", f.src)
	}

	f.Name = prefix //this is the name of the function that appears in the final src
	var err error
	f.Params, err = extractParams(body, f) //this is all the params we found
	if err != nil {
		return nil, err
	}
	if f.Propermode == "raw" {
		f.Params = append([]*Param{&Param{
			Name: "sysid",
			Type: "uint16",
		}}, f.Params...)
	}

	// return values
	// must have *all* return values in ()'s I guess?
	_, body, s, found = extractSection(s, '(', ')')
	if found {
		//we have a bunch of name/type pairs
		r, err := extractParams(body, f)
		if err != nil {
			return nil, err
		}
		switch len(r) {
		case 0: //no return - probs not a good sign tbh
		case 1: //one return, can only be err or some ret val I guess?
			if r[0].IsError() {
				f.Rets.ReturnsError = true
			} else {
				f.Rets.Name = r[0].Name
				f.Rets.Type = r[0].Type
			}
		case 2: //two returns
			if !r[1].IsError() { //this seems kinda cooked, but whatever. second return must be an error type
				return nil, errors.New("Only last windows error is allowed as second return value in \"" + f.src + "\"")
			}
			f.Rets.ReturnsError = true
			f.Rets.Name = r[0].Name
			f.Rets.Type = r[0].Type
		default:
			return nil, errors.New("Too many return values in \"" + f.src + "\"")
		}
	}

	// success condition
	_, body, s, found = extractSection(s, '[', ']')
	if found {
		f.Rets.SuccessCond = body
	}

	s = strings.TrimSpace(s)
	if s == "" {
		return f, nil
	}
	if !strings.HasPrefix(s, "=") {
		return nil, errors.New("Could not extract dll name from \"" + f.src + "\"")
	}
	s = strings.TrimSpace(s[1:])
	a := strings.Split(s, ".")
	switch len(a) {
	case 1:
		f.dllfuncname = a[0]
	case 2:
		f.dllname = a[0]
		f.dllfuncname = a[1]
	default:
		return nil, errors.New("Could not extract dll name from \"" + f.src + "\"")
	}

	return f, nil
}

// HasStringParam is true, if f has at least one string parameter.
// Otherwise it is false. This requires us to wrap it, and provide a byte pointer - this is done by creating a helper function rather than wrapping it in the func body because?????? idk
func (f *Fn) HasStringParam() bool {
	for _, p := range f.Params {
		if p.Type == "string" {
			return true
		}
	}
	return false
}

// HelperName returns name of function f helper.
func (f *Fn) HelperName() string {
	if !f.HasStringParam() {
		return f.Name
	}
	return "_" + f.Name
}

// HelperParamList returns source code for helper function f parameters.
func (f *Fn) HelperParamList() string {
	r := join(f.Params, func(p *Param) string { return p.Name + " " + p.HelperType() }, ", ")
	if f.mode == "raw" {
		r = "sysid uint16, " + r
	}
	return r
}

// StrconvType returns Go type name used for OS string for f.
func (f *Fn) StrconvType() string {
	if f.IsUTF16() {
		return "*uint16"
	}
	return "*byte"
}

// IsUTF16 is true, if f is W (utf16) function. It is false
// for all A (ascii) functions.
func (f *Fn) IsUTF16() bool {
	s := f.DLLFuncName()
	return s[len(s)-1] == 'W'
}

// DLLFuncName returns DLL function name for function f.
func (f *Fn) DLLFuncName() string {
	if f.dllfuncname == "" {
		return f.Name
	}
	return f.dllfuncname
}

//BananaLoader is which technique BananaPhone should use to resolve syscalls. A raw loader does not load syscalls at all (if the user wants to bundle syscalls directly, without resolving dynamic)
func (f *Fn) BananaLoader() string {
	if f.Propermode == "raw" {
		return `` //no loader, because user indicates they know what they are doing :smirkemoji:
	}
	yaboi := ``
	if f.Global {
		yaboi = `if bpGlobal == nil {` + //check if our bp is nill or not (maybe something broke it during  init?)
			`
		err = fmt.Errorf("BananaPhone uninitialised: %%s", bperr.Error())
		return
	}
	`
	} else {
		t := `bp, bperr := %sNewBananaPhone(%s%s)`
		if f.Internal {
			yaboi = fmt.Sprintf(t, "", "", f.Propermode)
		} else {
			yaboi = fmt.Sprintf(t, "bananaphone.", "bananaphone.", f.Propermode)
		}
		yaboi += `
		if bperr != nil{
			return bperr
		}`
	}
	yaboi += `
	sysid, e := bp%s.GetSysID("%s") ` + //resolve the functions and extract the syscall ID
		`
	if e != nil {
		err = e
		return
	}`
	return fmt.Sprintf(yaboi, f.GetGlobalVar(), f.DLLFuncName())
}

func (f *Fn) GetGlobalVar() string {
	if f.Global {
		return "Global"
	}
	return ""
}

// StrconvFunc returns name of Go string to OS string function for f.
func (f *Fn) StrconvFunc() string {
	if f.IsUTF16() {
		return "syscall.UTF16PtrFromString"
	}
	return "syscall.BytePtrFromString"
}

// BananaphoneSyscall returns the syscall function with a package init thing if needed
func (f *Fn) BananaphoneSyscall() string {
	prefix := "bananaphone."
	if f.Internal {
		prefix = ""
	}
	return prefix + "Syscall"
}

// ParamPrintList returns source code of trace printing part correspondent
// to syscall input parameters.
func (f *Fn) ParamPrintList() string {
	return join(f.Params, func(p *Param) string { return fmt.Sprintf(`"%s=", %s, `, p.Name, p.Name) }, `", ", `)
}

// SyscallParamList returns source code for SyscallX parameters for function f.
func (f *Fn) SyscallParamList() string {
	a := make([]string, 0)
	for i, p := range f.Params {
		if f.Propermode == "raw" && i == 0 {
			continue
		}
		a = append(a, p.SyscallArgList()...)
	}

	return strings.Join(a, ", ")
}
