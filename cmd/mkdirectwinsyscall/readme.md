# mkdirectwinsyscall

**warning** This code, and interface is likely to change. If you use it and it works, that's rad, but it might not work and/or break interfaces on the next commit. pls no rely on it (yet) thx.

This is mostly a re-write of go/src/golang.org/x/sys/windows/mkwinsyscall to fit in with bananaphone good.

## Flags
### Mode
`-mode`
Option  | Description
------------- | -------------
auto  | Automatically resolves sysID. First attempts to resolve in-memory, then falls back to disk. This is the default option.
memory  | Resolves sysID's by locating ntdll in memory by parsing the PEB, enumerating exports, and extracting the sysID from the function pointers.
disk | Resolves sysID's by parsing ntdll on-disk. Uses filesystem read API's built in to go.
raw | Does not resolve sysID's. Functions must be provided the sysID externally. (this may be useful if you want to hard-code them into the bin to avoid detection on resolution).

### Globals
`-noglobal`

This option will not use a global var for sys ID resolution. This means the PEB will be parsed/ntdll.dll on disk will be read *every time* the generated function is called. This might be what you want for some insane reason, no judgement here.

### Tracing
`-trace`

Is everything just not really working, and you have no idea what values are being given to your syscalls? This option will print every param + the returns etc for your debugging pleasure. It uses `print(` which I didn't even realise was a thing until I saw it in mkwinsyscall! TIL!

### Output
`-output`

Specify the output filename. This overwrites the file if it exists (because that's useful when doing `go generate`).

## Usage

It's recommended that you have a file specific for your syscalls, but in theory, you only need the following signature:

```golang
//dsys funcname(param type) (err error)
```

You can optionally include a suffix that allows you to have a different go function name, but calls a specified Windows API call. Below will create a func named `whateveryouwant()`, and resolve the `NtAllocateVirtualMemory` syscall ID.

```golang
//dsys whateveryouwant() (err error) = NtAllocateVirtualMemory
```

so for example, if you wanted to bananaphone up a `NtAllocateVirtualMemory` call, but not export it you would do this:
```golang
/*
//dsys ntAllocateVirtualMemory(processHandle syscall.Handle, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uint64, protect uint64) (err error) = NtAllocateVirtualMemory
```

Once you have your syscall.go file (or whatever it's called), you can run this program against it (`mkdirectwinsyscall syscall.go`). By default this will print to stdout.

Pro move is to use `go generate` to do it all for you. Include a line like this in `syscall.go` and then run `go generate .` in the package that has the file:

```golang
//go:generate go run github.com/C-Sto/BananaPhone/cmd/mkdirectwinsyscall -output zsyscall_windows.go syscall.go
```

This will run the generator, and replace the zsyscall_windows.go file with a newly generated version.


## Success/Error values:

See ntstatus.go

As far as I can tell, all Nt function calls (which are the only relevant function calls in this lib besides Zw) have a single return value of type NtStatus. This is a 32 bit value (https://doxygen.reactos.org/d9/d6f/base_2applications_2drwtsn32_2precomp_8h.html#a1b7a3ae6a8dcfbde0f16bfaffa13b024) with a bunch of different possible meanings. The `os` or `syscall` package should probably support these values better than I can.

At present, the return value for the `Syscall` function is *always* checked against 0, and if not 0, err is filled with a message that contains the hex representation of NtStatus (incase your func def omitted it, but still had the err value for some reason). If your return is between 0 and 0x3FFFFFFF, you need to check the err value for that, or specify the expected value in `[]`'s, just like the normal mkwinsyscall.