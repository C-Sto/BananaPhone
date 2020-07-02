package bananaphone

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
//sys NtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uint32, protect uint32) (err error) <auto>

//sys NtAllocateVirtualMemoryManual(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uint32, protect uint32) (err error) <raw>

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
//sys NtProtectVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, NewProtect uint32, oldprotect *uintptr) (err error) <auto>

//NtProtectVirtualMemoryManual See NtProtectVirtualMemory
//sys NtProtectVirtualMemoryManual(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, NewProtect uint32, oldprotect *uintptr) (err error) <raw>

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
//sys NtCreateThreadEx(hostThread *uintptr, DesiredAccess uintptr, ObjectAttributes uintptr, ProcessHandle uintptr, LpStartAddress uintptr, LpParameter uintptr, Createsuspended uintptr, StackZeroBits uintptr, sizeofstackcommit uintptr, SizeOfStackReserve uintptr, lpBytesBuffer uintptr) (err error)

//sys NtCreateThreadExManual(hostThread *uintptr, DesiredAccess uintptr, ObjectAttributes uintptr, ProcessHandle uintptr, LpStartAddress uintptr, LpParameter uintptr, Createsuspended uintptr, StackZeroBits uintptr, sizeofstackcommit uintptr, SizeOfStackReserve uintptr, lpBytesBuffer uintptr) (err error) <raw>

//go:generate go run github.com/C-Sto/BananaPhone/cmd/mkwinsyscall -output zautosyscall_windows.go autofuncs.go
