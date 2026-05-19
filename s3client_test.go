package main

import (
	"os"
	"path/filepath"
	"testing"
)

// withFakeHome stubs $HOME so LoadProfileData reads from a controlled directory.
func withFakeHome(t *testing.T, credentials, config string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	if credentials != "" {
		if err := os.WriteFile(filepath.Join(dir, ".aws", "credentials"), []byte(credentials), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if config != "" {
		if err := os.WriteFile(filepath.Join(dir, ".aws", "config"), []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", dir)
}

func TestLoadProfileData_VastFormat(t *testing.T) {
	// Exactly the format the user pasted: nested s3 block followed by more keys.
	config := `[profile var204]
region = us-east-1
s3 =
    addressing_style = path
output = json
endpoint_url = https://main.selab-var204.selab.vastdata.com
`
	credentials := `[var204]
aws_access_key_id = AAPHD13RSSKQ53355Y58
aws_secret_access_key = JO6Di1aROK6vtLK7oqBFYoQCZ6E/kWkAK985uShI
`
	withFakeHome(t, credentials, config)

	pd := LoadProfileData("var204")
	if pd.Region != "us-east-1" {
		t.Errorf("region = %q, want us-east-1", pd.Region)
	}
	if pd.Endpoint != "https://main.selab-var204.selab.vastdata.com" {
		t.Errorf("endpoint = %q, want https://main.selab-var204.selab.vastdata.com", pd.Endpoint)
	}
	if pd.AccessKey != "AAPHD13RSSKQ53355Y58" {
		t.Errorf("access key = %q, want AAPHD13RSSKQ53355Y58", pd.AccessKey)
	}
	if pd.SecretKey == "" {
		t.Errorf("secret key missing")
	}
}

func TestLoadProfileData_DefaultSectionName(t *testing.T) {
	config := `[default]
region = eu-west-1
endpoint_url = https://s3.example.com
`
	credentials := `[default]
aws_access_key_id = AKIAEXAMPLE
aws_secret_access_key = SECRETEXAMPLE
`
	withFakeHome(t, credentials, config)

	pd := LoadProfileData("default")
	if pd.Region != "eu-west-1" {
		t.Errorf("region = %q", pd.Region)
	}
	if pd.Endpoint != "https://s3.example.com" {
		t.Errorf("endpoint = %q", pd.Endpoint)
	}
}

func TestDiscoverProfiles_Vast(t *testing.T) {
	config := `[profile var204]
region = us-east-1
endpoint_url = https://main.selab-var204.selab.vastdata.com

[profile other]
region = us-west-2
`
	credentials := `[var204]
aws_access_key_id = X
aws_secret_access_key = Y
`
	withFakeHome(t, credentials, config)
	got := DiscoverProfiles()
	want := map[string]bool{"var204": true, "other": true}
	for _, p := range got {
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("missing profiles: %v (got %v)", want, got)
	}
}
