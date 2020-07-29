package main

import (
	"syscall"
)

func main() {
	var phandle syscall.Handle
	var baseA, zerob, regionsize uintptr
	var alloctype, protect uint64

	phandle = 0xffffffffffffffff //special macro to say 'this process'
	regionsize = uintptr(0x50000)
	protect = syscall.PAGE_EXECUTE_READWRITE
	alloctype = 0x3000 //MEM_COMMIT | MEM_RESERVE

	e := NtAllocateVirtualMemory(phandle, &baseA, zerob, &regionsize, alloctype, protect)
	if e != nil {
		panic(e)
	}
}
