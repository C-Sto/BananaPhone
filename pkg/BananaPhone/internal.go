package bananaphone

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/awgh/rawreader"
	"github.com/binject/debug/pe"
	"golang.org/x/sys/windows"
)

//rvaToOffset converts an RVA value from a PE file into the file offset. When using binject/debug, this should work fine even with in-memory files.
func rvaToOffset(pefile *pe.File, rva uint32) uint32 {
	for _, hdr := range pefile.Sections {
		baseoffset := uint64(rva)
		if baseoffset > uint64(hdr.VirtualAddress) &&
			baseoffset < uint64(hdr.VirtualAddress+hdr.VirtualSize) {
			return rva - hdr.VirtualAddress + hdr.Offset
		}
	}
	return rva
}

//getSysIDFromMemory takes values to resolve, and resolves in-memory.
func getSysIDFromMemory(funcname string, ord uint32, useOrd bool) (uint16, error) {
	start, size := GetNtdllStart()
	rr := rawreader.New(start, int(size))
	p, e := pe.NewFileFromMemory(rr)
	if e != nil {
		return 0, e
	}

	ex, e := p.Exports()
	if e != nil {
		return 0, e
	}

	for _, exp := range ex {
		if (useOrd && exp.Ordinal == ord) || // many bothans died for this feature
			exp.Name == funcname {
			offset := rvaToOffset(p, exp.VirtualAddress)
			b, e := p.Bytes()
			if e != nil {
				return 0, e
			}
			buff := b[offset : offset+10]

			return sysIDFromRawBytes(buff)
		}
	}
	return 0, errors.New("Could not find syscall ID")
}

//getSysIDFromMemory takes values to resolve, and resolves from disk.
func getSysIDFromDisk(funcname string, ord uint32, useOrd bool) (uint16, error) {
	l := `C:\Windows\system32\ntdll.dll`
	p, e := pe.Open(l)

	if e != nil {
		return 0, e
	}

	ex, e := p.Exports()
	for _, exp := range ex {
		if (useOrd && exp.Ordinal == ord) || // many bothans died for this feature
			exp.Name == funcname {
			offset := rvaToOffset(p, exp.VirtualAddress)
			b, e := p.Bytes()
			if e != nil {
				return 0, e
			}
			buff := b[offset : offset+10]

			return sysIDFromRawBytes(buff)
		}
	}
	return 0, errors.New("Could not find syscall ID")
}

//sysIDFromRawBytes takes a byte slice and determines if there is a sysID in the expected location. Returns a MayBeHookedError if the signature does not match.
func sysIDFromRawBytes(b []byte) (uint16, error) {
	if !bytes.HasPrefix(b, HookCheck) {
		return 0, MayBeHookedError{Foundbytes: b}
	}
	return binary.LittleEndian.Uint16(b[4:8]), nil
}

//stupidstring is the stupid internal windows definiton of a unicode string. I hate it.
type stupidstring struct {
	Length    uint16
	MaxLength uint16
	PWstr     *uint16
}

func (s stupidstring) String() string {
	return windows.UTF16PtrToString(s.PWstr)
}
