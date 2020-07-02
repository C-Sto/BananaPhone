package bananaphone

const (
	thisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
	memCommit  = uintptr(0x00001000)
	memreserve = uintptr(0x00002000)
)
