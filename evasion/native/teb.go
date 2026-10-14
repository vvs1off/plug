//go:build windows

package main

/*
#include <stdint.h>
#include <windows.h>

// Reading the TEB from C avoids both a Go assembly file (which cgo packages
// reject) and any loader API — no GetModuleHandle, no LoadLibrary, nothing an
// EDR hook can sit on. __readgsqword(0x30) is the x64 TEB pointer.
static uintptr_t read_teb(void) {
#if defined(_M_X64) || defined(__x86_64__)
	return (uintptr_t)__readgsqword(0x30);
#else
	return 0;
#endif
}

// Read a pointer at an offset, used to walk PEB -> Ldr -> module list.
static uintptr_t read_ptr(uintptr_t base, uintptr_t offset) {
	return *(uintptr_t*)(base + offset);
}
*/
import "C"

// getTEB returns the Thread Environment Block pointer.
func getTEB() uintptr {
	return uintptr(C.read_teb())
}

// readPtr dereferences base+offset as a pointer.
func readPtr(base, offset uintptr) uintptr {
	return uintptr(C.read_ptr(C.uintptr_t(base), C.uintptr_t(offset)))
}
