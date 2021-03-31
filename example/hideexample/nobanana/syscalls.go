package main

//sys NtWriteVirtualMemory(hProcess uintptr, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error) = ntdll.NtWriteVirtualMemory
//sys NtAllocateVirtualMemory(hProcess uintptr, lpAddress *uintptr, zerobits uintptr, dwSize *uint32, flAllocationType uint32, flProtect uint32) (err error) = ntdll.NtAllocateVirtualMemory
//sys NtCreateThreadEx(hThread *uintptr, desiredaccess uintptr, objattrib uintptr, processhandle uintptr, lpstartaddr uintptr, lpparam uintptr, createsuspended uintptr, zerobits uintptr, sizeofstack uintptr, sizeofstackreserve uintptr, lpbytesbuffer uintptr) (err error) = ntdll.NtCreateThreadEx

//go:generate go run $GOPATH/src/golang.org/x/sys/windows/mkwinsyscall -trace -output zsyscalls_windows.go syscalls.go
