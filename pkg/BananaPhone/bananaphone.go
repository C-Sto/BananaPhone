package bananaphone

import (
	"errors"
	"fmt"

	"github.com/awgh/rawreader"
	"github.com/binject/debug/pe"
)

//PhoneMode determines the way a bananaphone will resolve sysids
type PhoneMode int

const (
	//MemoryBananaPhoneMode will resolve by finding the PEB in-memory, and enumerating the loaded ntdll.dll to resolve exports and determine the sysid.
	MemoryBananaPhoneMode PhoneMode = iota
	//DiskBananaPhoneMode will resolve by loading ntdll.dll from disk, and enumerating to resolve exports and determine the sysid.
	DiskBananaPhoneMode
	//AutoBananaPhoneMode will resolve by first trying to resolve in-memory, and then falling back to loading from disk if in-memory fails (eg, if it's hooked and the sysid's have been moved).
	AutoBananaPhoneMode
)

//BananaPhone will resolve SysID's used for syscalls while making minimal API calls. These ID's can be used for functions like NtAllocateVirtualMemory as defined in functions.go.
type BananaPhone struct {
	banana *pe.File
	isAuto bool
}

//NewBananaPhone creates a new instance of a bananaphone with behaviour as defined by the input value. Use AutoBananaPhoneMode if you're not sure.
/*
Possible values:
	- MemoryBananaPhoneMode
	- DiskBananaPhoneMode
	- AutoBananaPhoneMode
*/
func NewBananaPhone(t PhoneMode) (*BananaPhone, error) {
	var p *pe.File
	var e error

	switch t {
	case AutoBananaPhoneMode:
		fallthrough
	case MemoryBananaPhoneMode:
		start, size := GetNtdllStart()
		rr := rawreader.New(start, int(size))
		p, e = pe.NewFileFromMemory(rr)

	case DiskBananaPhoneMode:
		p, e = pe.Open(`C:\Windows\system32\ntdll.dll`)
	}

	return &BananaPhone{
		banana: p,
		isAuto: t == AutoBananaPhoneMode,
	}, e
}

//GetSysID resolves the provided function name into a sysid.
func (b *BananaPhone) GetSysID(funcname string) (uint16, error) {
	r, e := b.getSysID(funcname, 0, false)
	if e != nil {
		var err MayBeHookedError
		if b.isAuto && errors.As(e, &err) {
			var e2 error
			b.banana, e2 = pe.Open(`C:\Windows\system32\ntdll.dll`)
			if e2 != nil {
				return 0, e2
			}
			r, e = b.getSysID(funcname, 0, false)
		}
	}
	return r, e
}

//GetSysIDOrd resolves the provided ordinal into a sysid.
func (b *BananaPhone) GetSysIDOrd(ordinal uint32) (uint16, error) {
	r, e := b.getSysID("", ordinal, true)
	if e != nil {
		var err MayBeHookedError
		if b.isAuto && errors.Is(e, &err) {
			var e2 error
			b.banana, e2 = pe.Open(`C:\Windows\system32\ntdll.dll`)
			if e2 != nil {
				return 0, e2
			}
			r, e = b.getSysID("", ordinal, true)
		}
	}
	return r, e
}

//getSysID does the heavy lifting - will resolve a name or ordinal into a sysid by getting exports, and parsing the first few bytes of the function to extract the ID. Doens't look at the ord value unless useOrd is set to true.
func (b BananaPhone) getSysID(funcname string, ord uint32, useOrd bool) (uint16, error) {
	ex, e := b.banana.Exports()
	if e != nil {
		return 0, e
	}

	for _, exp := range ex {
		if (useOrd && exp.Ordinal == ord) || // many bothans died for this feature (thanks awgh). Turns out that a value can be exported by ordinal, but not by name! man I love PE files. ha ha jk.
			exp.Name == funcname {
			offset := rvaToOffset(b.banana, exp.VirtualAddress)
			b, e := b.banana.Bytes()
			if e != nil {
				return 0, e
			}
			buff := b[offset : offset+10]

			return sysIDFromRawBytes(buff)
		}
	}
	return 0, errors.New("Could not find syscall ID")
}

//MayBeHookedError an error returned when trying to extract the sysid from a resolved function. Contains the bytes that were actually found (incase it's useful to someone?)
type MayBeHookedError struct {
	Foundbytes []byte
}

func (e MayBeHookedError) Error() string {
	return fmt.Sprintf("may be hooked: wanted %x got %x", HookCheck, e.Foundbytes)
}

//HookCheck is the bytes expected to be seen at the start of the function:
/*
	mov r10, rcx ;(4c 8b d1)
	mov eax, sysid ;(b8 sysid)
*/
var HookCheck = []byte{0x4c, 0x8b, 0xd1, 0xb8}
