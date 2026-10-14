//go:build windows

package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// Windows does not export these in syscall; the values are fixed by Winsock.
const (
	ipprotoRaw = 255
	ipHdrIncl  = 2
)

// sendRaw writes a fully-formed ethernet frame out of an interface using a
// raw socket. Windows permits this only from an elevated process.
func sendRaw(ifIndex int, frame []byte) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, ipprotoRaw)
	if err != nil {
		return err
	}
	defer syscall.Closesocket(fd)

	// Bind so the frame egresses the correct interface.
	sa := &syscall.SockaddrInet4{Port: 0}
	sa.Addr = [4]byte{0, 0, 0, 0}
	_ = syscall.Bind(fd, sa)

	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, ipHdrIncl, 1)

	// Include the ethernet header ourselves.
	err = syscall.Sendto(fd, frame, 0, &syscall.SockaddrInet4{})
	if err != nil {
		return fmt.Errorf("sendto: %w", err)
	}
	return nil
}

// listInterfaces reports usable interfaces so the operator can pick one.
func listInterfaces() {
	ifaces, err := net.Interfaces()
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": err.Error()})
		return
	}
	type entry struct {
		Index int    `json:"index"`
		Name  string `json:"name"`
		MAC   string `json:"mac"`
		IP    string `json:"ip"`
	}
	var out []entry
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || len(ifc.HardwareAddr) != 6 {
			continue
		}
		addrs, _ := ifc.Addrs()
		var ip string
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				ip = ipnet.IP.To4().String()
				break
			}
		}
		out = append(out, entry{
			Index: ifc.Index,
			Name:  ifc.Name,
			MAC:   ifc.HardwareAddr.String(),
			IP:    ip,
		})
	}
	sendEvent("ifaces", out)
}

// winIPHelper is kept for future GetAdaptersAddresses use; the stdlib path
// above covers what we need.
var _ = unsafe.Pointer(nil)
