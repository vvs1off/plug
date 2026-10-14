//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Named pipe I/O over the SMB2 session
// ---------------------------------------------------------------------------

// writePipe sends bytes into an open pipe handle.
func (c *smbClient) writePipe(fileID, data []byte) error {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(49))
	binary.Write(&b, binary.LittleEndian, uint16(112)) // DataOffset (patched)
	binary.Write(&b, binary.LittleEndian, uint32(len(data)))
	binary.Write(&b, binary.LittleEndian, uint64(0)) // offset
	b.Write(fileID)
	binary.Write(&b, binary.LittleEndian, uint32(0)) // channel
	binary.Write(&b, binary.LittleEndian, uint32(0)) // remaining
	binary.Write(&b, binary.LittleEndian, uint16(0)) // write channel info offset
	binary.Write(&b, binary.LittleEndian, uint16(0)) // write channel info length
	binary.Write(&b, binary.LittleEndian, uint32(0)) // flags
	b.Write(data)

	body := b.Bytes()
	binary.LittleEndian.PutUint16(body[2:4], uint16(smb2HeaderSize+48))

	rh, _, err := c.send(smb2Write, body, c.treeID)
	if err != nil {
		return err
	}
	if rh.Status != statusSuccess {
		return fmt.Errorf("pipe write: %s", statusName(rh.Status))
	}
	return nil
}

// transceivePipe issues FSCTL_PIPE_TRANSCEIVE, which both writes a request and
// reads its reply — the correct primitive for RPC over a pipe.
func (c *smbClient) transceivePipe(fileID []byte) ([]byte, error) {
	outBuf := make([]byte, 65536)

	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(57))  // StructureSize
	binary.Write(&b, binary.LittleEndian, uint16(0))   // Reserved
	binary.Write(&b, binary.LittleEndian, uint32(1))   // CtlCode: FSCTL_PIPE_TRANSCEIVE
	b.Write(fileID)                                     // 16-byte FileId
	binary.Write(&b, binary.LittleEndian, uint32(0))   // InputOffset (patched)
	binary.Write(&b, binary.LittleEndian, uint32(0))   // InputCount
	binary.Write(&b, binary.LittleEndian, uint32(0))   // MaxInputResponse
	binary.Write(&b, binary.LittleEndian, uint32(112)) // OutputOffset (patched)
	binary.Write(&b, binary.LittleEndian, uint32(len(outBuf)))
	binary.Write(&b, binary.LittleEndian, uint32(0))   // MaxOutputResponse
	binary.Write(&b, binary.LittleEndian, uint32(1))   // Flags: FSCTL_IS_FSCTL

	body := b.Bytes()
	binary.LittleEndian.PutUint32(body[40:44], uint32(smb2HeaderSize+56))
	binary.LittleEndian.PutUint32(body[52:56], uint32(smb2HeaderSize+56))

	rh, resp, err := c.send(smb2Ioctl, body, c.treeID)
	if err != nil {
		return nil, err
	}
	if rh.Status != statusSuccess {
		return nil, fmt.Errorf("pipe transceive: %s", statusName(rh.Status))
	}
	// OutputOffset/OutputCount live at 32 and 36 in the IOCTL response body.
	if len(resp) < 48 {
		return nil, fmt.Errorf("short ioctl response")
	}
	off := int(binary.LittleEndian.Uint32(resp[32:36])) - smb2HeaderSize
	count := int(binary.LittleEndian.Uint32(resp[36:40]))
	if off < 0 || off+count > len(resp) || count <= 0 {
		return nil, fmt.Errorf("bad ioctl output bounds")
	}
	return resp[off : off+count], nil
}

// ---------------------------------------------------------------------------
// WMI execution
//
// WMI goes over DCOM on 135, which is a different transport from SMB. With a
// password we can hand the whole thing to PowerShell; with a hash we first
// establish a logon session that carries the hash, then reuse it.
// ---------------------------------------------------------------------------

func wmiExec(host string, cred *credential, localPath string) error {
	switch cred.Kind {
	case credPassword:
		return wmiExecPassword(host, cred, localPath)

	case credHash:
		// Windows has no public API to open a network logon from a bare hash,
		// so we surface this honestly instead of pretending it worked.
		return fmt.Errorf("WMI does not accept an NT hash; use psexec or schtasks over SMB2")

	case credTicket:
		return fmt.Errorf("WMI does not accept a Kerberos ticket in this build; use psexec over SMB2")
	}
	return fmt.Errorf("unsupported credential for WMI")
}

func wmiExecPassword(host string, cred *credential, localPath string) error {
	user := cred.User
	if cred.Domain != "" {
		user = cred.Domain + `\` + cred.User
	}

	script := fmt.Sprintf(
		`$sec = ConvertTo-SecureString '%s' -AsPlainText -Force; `+
			`$cred = New-Object System.Management.Automation.PSCredential('%s', $sec); `+
			`$c = Get-WmiObject -Class Win32_Process -ComputerName '%s' -Credential $cred -List; `+
			`$c | Invoke-WmiMethod -Name Create -ArgumentList '%s'`,
		escapePS(cred.Password), escapePS(user), host, localPath)

	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wmi: %s", strings.TrimSpace(string(out)))
	}
	if strings.Contains(string(out), "ReturnValue") && !strings.Contains(string(out), ": 0") {
		return fmt.Errorf("wmi returned non-zero")
	}
	return nil
}

var _ = time.Now
