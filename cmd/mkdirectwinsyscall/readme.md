# mkdirectwinsyscall

**warning** This code, and interface is likely to change. If you use it and it works, that's rad, but it might not work and/or break interfaces on the next commit. pls no rely on it (yet) thx.

This is mostly a re-write of go/src/golang.org/x/sys/windows/mkwinsyscall to fit in with bananaphone good.

Todo: write usage/docs/reference etc for this

## Scucess/Error values:

See ntstatus.go

As far as I can tell, all Nt function calls (which are the only relevant function calls in this lib besides Zw) have a single return value of type NtStatus. This is a 32 bit value (https://doxygen.reactos.org/d9/d6f/base_2applications_2drwtsn32_2precomp_8h.html#a1b7a3ae6a8dcfbde0f16bfaffa13b024) with a bunch of different possible meanings. The `os` or `syscall` package should probably support these values better than I can.

At present, the return value for the `Syscall` function is *always* checked against 0, and if not 0, err is filled with a message that contains the hex representation of NtStatus (incase your func def omitted it, but still had the err value for some reason). If your return is between 0 and 0x3FFFFFFF, you need to check the err value for that, or specify the expected value in `[]`'s, just like the normal mkwinsyscall.