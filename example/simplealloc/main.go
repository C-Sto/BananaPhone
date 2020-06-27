package main

import (
	"fmt"
	"syscall"
	"unsafe"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
)

func main() {
	var phandle, baseA, zerob, regionsize, alloctype, protect uintptr

	phandle = 0xffffffffffffffff //special macro to say 'this process'
	regionsize = uintptr(0x50000)
	protect = syscall.PAGE_EXECUTE_READWRITE
	alloctype = 0x3000 //MEM_COMMIT | MEM_RESERVE

	sysid, err := bananaphone.GetSysIDFromMemory("NtAllocateVirtualMemory")
	if err != nil {
		panic(err)
	}
	fmt.Println("SysID from memory (should be 0x18 on win 10)", fmt.Sprintf("%x", sysid))

	/*
		__kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
			HANDLE    ProcessHandle,
			PVOID     *BaseAddress,
			ULONG_PTR ZeroBits,
			PSIZE_T   RegionSize,
			ULONG     AllocationType,
			ULONG     Protect
			);
	*/

	r1, err := bananaphone.Syscall(
		sysid,                                //ntallocatevirtualmemory
		phandle,                              //this thread
		uintptr(unsafe.Pointer(&baseA)),      //empty base address (give us something anywhere)
		zerob,                                //0
		uintptr(unsafe.Pointer(&regionsize)), //pointer to size
		alloctype,                            //commit | reserve
		protect,                              //rwx
	)
	if r1 != 0 || err != nil {
		panic(err)
	}

	fmt.Printf("Base address of allocated memory: %x\n", baseA)
	start, size := bananaphone.GetNtdllStart()
	fmt.Printf("Start address of ntdll: %x size: %x\n", start, size)
}
