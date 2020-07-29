package main

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
//dsys NtAllocateVirtualMemory(processHandle syscall.Handle, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uint64, protect uint64) (err error) {

//go:generate go run github.com/C-Sto/BananaPhone/cmd/mkdirectwinsyscall -output zsyscall_windows.go syscall.go
