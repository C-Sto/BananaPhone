package main

/*
https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values?redirectedfrom=MSDN
NT_SUCCESS(Status)
Evaluates to TRUE if the return value specified by Status is a success type (0 − 0x3FFFFFFF) or an informational type (0x40000000 − 0x7FFFFFFF).

NT_INFORMATION(Status)
Evaluates to TRUE if the return value specified by Status is an informational type (0x40000000 − 0x7FFFFFFF).

NT_WARNING(Status)
Evaluates to TRUE if the return value specified by Status is a warning type (0x80000000 − 0xBFFFFFFF).

NT_ERROR(Status)
Evaluates to TRUE if the return value specified by Status is an error type (0xC0000000 - 0xFFFFFFFF).
*/
