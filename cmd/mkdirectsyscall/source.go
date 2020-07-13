package main

import (
	"bufio"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/template"
)

// ParseFiles parses files listed in fs and extracts all syscall
// functions listed in dsys comments. It returns a files
// and functions collection *Source if successful.
func ParseFiles(files []string) (*Source, error) {
	src := &Source{
		//Funcs: make([]*Fn, 0),
		Files: make([]string, 0),
		StdLibImports: []string{
			"unsafe",
		},
		ExternalImports: make([]string, 0),
	}
	for _, file := range files {
		if err := src.ParseFile(file); err != nil {
			return nil, err
		}
	}
	return src, nil
}

// Source files and functions.
type Source struct {
	Funcs           []*Fn
	Files           []string
	StdLibImports   []string
	ExternalImports []string
	PackageName     string
}

//Import adds an import to the current source (this should never really be called?)
func (src *Source) Import(pkg string) {
	src.StdLibImports = append(src.StdLibImports, pkg)
	sort.Strings(src.StdLibImports)
}

//ExternalImport adds an external import (eg, an import not from bananaphone)
func (src *Source) ExternalImport(pkg string) {
	src.ExternalImports = append(src.ExternalImports, pkg)
	sort.Strings(src.ExternalImports)
}

// DLLs return dll names for a source set src. (this shouldn't really be called either, we don't deal with dlls in bananaphone ok)
/*
func (src *Source) DLLs() []string {
	log.Println("Erm, maybe check this one eh! something is calling for DLL's lol")
	uniq := make(map[string]bool)
	r := make([]string, 0)
	for _, f := range src.Funcs {
		name := f.DLLName()
		if _, found := uniq[name]; !found {
			uniq[name] = true
			r = append(r, name)
		}
	}
	return r
}
*/

// ParseFile adds additional file path to a source set src.
// **note** this is a pretty weird way of doing it, we can probably tokenise and parse it better but uh.. you do you stdlib..
func (src *Source) ParseFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	for s.Scan() { //checks each line
		t := strings.TrimSpace(s.Text()) //ignore whitespace
		/*
			this probably avoids some false-positives but like... what?
			if len(t) < 7 {
				continue
			}
		*/
		if !strings.HasPrefix(t, marker) { //not what we are lookin for fam!
			continue
		}

		t = t[len(marker):] //skip marker

		//check for space/tab after the //dsys marker. Just incase someone wrote //dsysnuts or something I guess? idk
		if !(t[0] == ' ' || t[0] == '\t') {
			continue
		}
		t = strings.TrimSpace(t)

		//what's left should be a function definition. Let's parse that badboi!
		std, err := src.IsStdRepo()
		if err != nil {
			return err
		}
		f, err := NewFn(t, std)
		if err != nil {
			return err
		}
		src.Funcs = append(src.Funcs, f)

	}
	if err := s.Err(); err != nil {
		return err
	}

	src.Files = append(src.Files, path)

	// get package name
	fset := token.NewFileSet()
	_, err = file.Seek(0, 0)
	if err != nil {
		return err
	}
	pkg, err := parser.ParseFile(fset, "", file, parser.PackageClauseOnly)
	if err != nil {
		return err
	}
	src.PackageName = pkg.Name.Name

	return nil
}

// Generate output source file
func (src *Source) Generate(w io.Writer) error {

	//work out if this is being used from bananaphone or not :O bananaception! the phone is ringing from inside the package!
	/*
		isBananaRepo, err := src.IsStdRepo()
		if err != nil {
			return err
		}
	*/
	src.Import("syscall") //I think we will always need this?

	funcMap := template.FuncMap{ //I don't fully understand what's going on here
		"packagename":    src.GetPackageName,
		"bananaphonedot": src.Bananaphonedot,
	}

	t := template.Must(template.New("main").Funcs(funcMap).Parse(srcTemplate))
	err := t.Execute(w, src)
	if err != nil {
		return errors.New("Failed to execute template: " + err.Error())
	}
	return nil
}

// IsStdRepo reports whether src is part of standard library.
func (src *Source) IsStdRepo() (bool, error) {
	if len(src.Files) == 0 {
		return false, errors.New("no input files provided")
	}
	abspath, err := filepath.Abs(src.Files[0])
	if err != nil {
		return false, err
	}

	if runtime.GOOS == "windows" {
		abspath = strings.ToLower(abspath)
	}
	//this probably isn't the best way of checking, but it seems to work OK
	return strings.Contains(abspath, filepath.Join("github.com", "c-sto", "bananaphone", "pkg", "bananaphone")), nil
}

//Bananaphonedot returns the prefix to any bananaphone calls (or none, if it's inside the bp repo)
func (src Source) Bananaphonedot() string {
	if src.PackageName == "bananaphone" {
		return ""
	}
	return "bananaphone."
}

//GetPackageName returns the package name for the source set
func (src Source) GetPackageName() string {
	return src.PackageName
}

//BananaImport will return the import path for bananaphone, or an empty string if it's called from within this repo
func (src *Source) BananaImport() string {
	std, err := src.IsStdRepo()
	if err != nil {
		panic(err)
	}
	if !std {
		return `bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"`
	}
	return ``
}
