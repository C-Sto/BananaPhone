package main

//dsys NtWriteVirtualMemory(hProcess uintptr, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error) = ntdll.NtWriteVirtualMemory
//dsys NtAllocateVirtualMemory(hProcess uintptr, lpAddress *uintptr, zerobits uintptr, dwSize *uint32, flAllocationType uint32, flProtect uint32) (err error) = ntdll.NtAllocateVirtualMemory
//dsys NtProtectVirtualMemory(hProcess uintptr, lpAddress *uintptr, dwSize *uintptr, flNewProtect uint32, lpflOldProtect *uint32) (err error) = ntdll.NtProtectVirtualMemory
//dsys NtCreateThreadEx(hThread *uintptr, desiredaccess uintptr, objattrib uintptr, processhandle uintptr, lpstartaddr uintptr, lpparam uintptr, createsuspended uintptr, zerobits uintptr, sizeofstack uintptr, sizeofstackreserve uintptr, lpbytesbuffer uintptr) (err error) = ntdll.NtCreateThreadEx

//go:generate go run github.com/C-Sto/BananaPhone/cmd/mkdirectwinsyscall -trace -output zsyscall_windows.go syscalls.go
