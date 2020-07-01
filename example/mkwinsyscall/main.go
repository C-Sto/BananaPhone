package main

import (
	"syscall"
)

func main() {
	var phandle, baseA, zerob, regionsize, alloctype, protect uintptr

	phandle = 0xffffffffffffffff //special macro to say 'this process'
	regionsize = uintptr(0x50000)
	protect = syscall.PAGE_EXECUTE_READWRITE
	alloctype = 0x3000 //MEM_COMMIT | MEM_RESERVE

	e := NtAllocateVirtualMemory(phandle, &baseA, zerob, &regionsize, alloctype, protect)
	if e != nil {
		panic(e)
	}
}

//go:generate go run github.com/C-Sto/BananaPhone/cmd/mkwinsyscall -output zsyscall_windows.go syscall.go
