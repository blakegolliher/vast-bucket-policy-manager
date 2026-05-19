package app

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// backupRoot is the top-level directory under $HOME where snapshots live.
// Exposed for tests so they can redirect to a temp dir.
var backupRoot = ".vast-bucket-manager"

var endpointUnsafe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// SanitizeEndpoint turns "https://main.selab-var204.selab.vastdata.com/" into
// a filename-safe segment "main.selab-var204.selab.vastdata.com". Exported
// for the tests/ package; also used internally by backupDir.
func SanitizeEndpoint(ep string) string {
	ep = strings.TrimSpace(ep)
	ep = strings.TrimPrefix(ep, "https://")
	ep = strings.TrimPrefix(ep, "http://")
	ep = strings.TrimSuffix(ep, "/")
	if ep == "" {
		return "aws"
	}
	return endpointUnsafe.ReplaceAllString(ep, "_")
}

// backupDir returns the directory for a given endpoint+bucket combination.
func backupDir(endpoint, bucket string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, backupRoot, SanitizeEndpoint(endpoint), bucket), nil
}

// WriteBackup writes a timestamped snapshot of a policy. kind is a short
// label such as "before-save", "after-save", or "before-delete". Returns the
// path written or an error.
//
// An empty content (no policy on the server) is recorded as a literal
// "(no policy)" marker so the file is grep-friendly.
func WriteBackup(endpoint, bucket, kind, content string) (string, error) {
	dir, err := backupDir(endpoint, bucket)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create backup dir: %w", err)
	}
	ts := time.Now().UTC().Format("20060102-150405")
	path := filepath.Join(dir, fmt.Sprintf("%s-%s.json", ts, kind))
	if strings.TrimSpace(content) == "" {
		content = "(no policy)\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}
	return path, nil
}
