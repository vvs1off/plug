//go:build windows

package main

import (
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Device struct {
	IP    string `json:"ip"`
	MAC   string `json:"mac"`
	Ports []int  `json:"ports"`
}

var arpLineRe = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})`)

var commonPorts = []int{21, 22, 23, 53, 80, 135, 139, 443, 445, 3389, 5000, 5432, 5985, 8000, 8080, 9000, 3306}

func scanNetwork() {
	sendEvent("status", map[string]interface{}{"state": "scanning", "detail": "reading ARP table"})

	devices := arpDevices()
	if len(devices) == 0 {
		sendEvent("error", map[string]interface{}{"message": "ARP table empty — no LAN hosts found"})
		sendEvent("status", map[string]interface{}{"state": "idle"})
		return
	}

	sendEvent("status", map[string]interface{}{"state": "scanning", "detail": "port scanning " + strconv.Itoa(len(devices)) + " hosts"})

	var wg sync.WaitGroup
	for i := range devices {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			devices[i].Ports = scanPorts(devices[i].IP)
		}(i)
	}
	wg.Wait()

	// sort by IP
	sort.Slice(devices, func(a, b int) bool { return ipLess(devices[a].IP, devices[b].IP) })

	sendEvent("devices", devices)
	sendEvent("status", map[string]interface{}{"state": "done", "detail": "found " + strconv.Itoa(len(devices)) + " devices"})
}

func arpDevices() []Device {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil
	}
	seen := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		m := arpLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ip, mac := m[1], strings.ToUpper(m[2])
		if ip == "255.255.255.255" || strings.HasPrefix(ip, "224.") || strings.HasPrefix(ip, "239.") {
			continue
		}
		if mac == "FF-FF-FF-FF-FF-FF" {
			continue
		}
		if _, ok := seen[ip]; !ok {
			seen[ip] = mac
		}
	}
	var out2 []Device
	for ip, mac := range seen {
		out2 = append(out2, Device{IP: ip, MAC: mac})
	}
	return out2
}

func scanPorts(ip string) []int {
	var open []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)
	for _, p := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(p)), 400*time.Millisecond)
			if err == nil {
				_ = conn.Close()
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

func ipLess(a, b string) bool {
	pa := net.ParseIP(a).To4()
	pb := net.ParseIP(b).To4()
	if pa == nil || pb == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}
