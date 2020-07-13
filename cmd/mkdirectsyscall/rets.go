package main

// Rets describes function return parameters.
type Rets struct {
	Name         string
	Type         string
	ReturnsError bool
	SuccessCond  string
}

// List returns source code of syscall return parameters.
func (r *Rets) List() string {
	s := join(r.ToParams(), func(p *Param) string { return p.Name + " " + p.Type }, ", ")
	if len(s) > 0 {
		s = "(" + s + ")"
	}
	return s
}

// ToParams converts r into slice of *Param.
func (r *Rets) ToParams() []*Param {
	ps := make([]*Param, 0)
	if len(r.Name) > 0 {
		ps = append(ps, &Param{Name: r.Name, Type: r.Type})
	}
	if r.ReturnsError {
		ps = append(ps, &Param{Name: "err", Type: "error"})
	}
	return ps
}
