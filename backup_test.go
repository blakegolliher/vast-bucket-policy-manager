package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://main.selab-var204.selab.vastdata.com": "main.selab-var204.selab.vastdata.com",
		"http://10.0.0.5:8443/":                        "10.0.0.5_8443",
		"":                                             "aws",
		"https://s3.us-east-1.amazonaws.com":           "s3.us-east-1.amazonaws.com",
		"foo bar/baz":                                  "foo_bar_baz",
	}
	for in, want := range cases {
		if got := sanitizeEndpoint(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteBackup(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	path, err := WriteBackup("https://s3.example.com", "my-bucket", "before-save", `{"Version":"2012-10-17"}`)
	if err != nil {
		t.Fatalf("WriteBackup: %v", err)
	}
	if !strings.Contains(path, filepath.Join(".vast-bucket-manager", "s3.example.com", "my-bucket")) {
		t.Errorf("unexpected backup path: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != `{"Version":"2012-10-17"}` {
		t.Errorf("content mismatch: %s", string(data))
	}

	// Empty content should be recorded as a marker, not silently produce
	// an empty file (which would be ambiguous with "policy was empty string").
	path2, err := WriteBackup("https://s3.example.com", "my-bucket", "before-delete", "")
	if err != nil {
		t.Fatal(err)
	}
	data2, _ := os.ReadFile(path2)
	if !strings.Contains(string(data2), "no policy") {
		t.Errorf("expected (no policy) marker, got %q", string(data2))
	}
}
