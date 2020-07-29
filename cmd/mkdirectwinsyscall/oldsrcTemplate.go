package main

//this file is here so that I don't lose track of what the template used to look like. Template is probably not the best option for this tbh.

// package main

// const srcTemplate = `
// {{define "main"}}// Code generated by 'go generate'; DO NOT EDIT.

// package {{packagename}}
// import (
// 	{{range .StdLibImports}}"{{.}}"
// 	{{end}}
// 	{{range .ExternalImports}}"{{.}}"
// 	{{end}}
// 	{{.BananaImport}}
// )

// var _ unsafe.Pointer

// // Do the interface allocations only once for common
// // Errno values. C_Sto note: this feels like it might be important, so I'm keeping it.
// const (
// 	errnoERROR_IO_PENDING = 997
// )

// var (
// 	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
// )

// // errnoErr returns common boxed Errno values, to prevent
// // allocations at runtime. (yep, again, dunno what it does, but it looks important..)
// func errnoErr(e syscall.Errno) error {
// 	switch e {
// 	case 0:
// 		return nil
// 	case errnoERROR_IO_PENDING:
// 		return errERROR_IO_PENDING
// 	}
// 	// TODO: add more here, after collecting data on the common
// 	// error values see on Windows. (perhaps when running
// 	// all.bat?)
// 	return e
// }

// {{.VarBlock}}

// {{range .Funcs}}{{if .HasStringParam}}{{template "helperbody" .}}{{end}}{{template "funcbody" .}}{{end}}
// {{end}}

// {{define "funcbody"}}
// func {{.HelperName}}({{.HelperParamList}}) {{template "results" .}}{
// 	{{.BananaLoader}}
// {{template "tmpvars" .}}	{{template "syscall" .}}	{{template "tmpvarsreadback" .}}
// {{template "seterror" .}}{{template "printtrace" .}}	return
// }
// {{end}}

// {{define "results"}}{{if .Rets.List}}{{.Rets.List}} {{end}}{{end}}

// {{define "bananaloader"}} {{end}}

// {{define "tmpvars"}}{{range .Params}}{{if .TmpVarCode}}	{{.TmpVarCode}}
// {{end}}{{end}}{{end}}

// {{define "syscall"}}{{.Rets.SetReturnValuesCode}}{{.BananaphoneSyscall}}(sysid, {{.SyscallParamList}}){{end}}

// {{define "tmpvarsreadback"}}{{range .Params}}{{if .TmpVarReadbackCode}}
// {{.TmpVarReadbackCode}}{{end}}{{end}}{{end}}

// {{define "seterror"}}{{if .Rets.SetErrorCode}}	{{.Rets.SetErrorCode}}
// {{end}}{{end}}

// {{define "printtrace"}}{{if .PrintTrace}}	print("SYSCALL: {{.Name}}(", {{.ParamPrintList}}") (", {{.Rets.PrintList}}")\n")
// {{end}}{{end}}

// `
