package tests

import (
	"testing"

	"github.com/vastdata/vast-bucket-manager/internal/app"
)

func TestValidatePolicy_Empty(t *testing.T) {
	f := app.ValidatePolicy("")
	if len(f) != 1 || f[0].Severity != app.SevError {
		t.Fatalf("expected one error finding, got %v", f)
	}
}

func TestValidatePolicy_BadJSON(t *testing.T) {
	f := app.ValidatePolicy(`{"Version": "2012-10-17",`)
	if !app.HasErrors(f) {
		t.Fatalf("expected errors for malformed JSON, got %v", f)
	}
	if f[0].Line == 0 {
		t.Errorf("expected line info, got %+v", f[0])
	}
}

func TestValidatePolicy_Valid(t *testing.T) {
	policy := `{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "AllowPublicRead",
          "Effect": "Allow",
          "Principal": "*",
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::mybucket/*"
        }
      ]
    }`
	f := app.ValidatePolicy(policy)
	if app.HasErrors(f) {
		t.Fatalf("expected no errors, got %v", f)
	}
}

func TestValidatePolicy_MissingEffect(t *testing.T) {
	policy := `{
      "Version": "2012-10-17",
      "Statement": [
        {"Principal":"*","Action":"s3:GetObject","Resource":"*"}
      ]
    }`
	f := app.ValidatePolicy(policy)
	if !app.HasErrors(f) {
		t.Fatalf("expected error for missing Effect, got %v", f)
	}
}

func TestValidatePolicy_BothActionAndNotAction(t *testing.T) {
	policy := `{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect":"Allow","Principal":"*",
        "Action":"s3:GetObject","NotAction":"s3:DeleteObject",
        "Resource":"*"
      }]
    }`
	f := app.ValidatePolicy(policy)
	if !app.HasErrors(f) {
		t.Fatalf("expected error for both Action and NotAction, got %v", f)
	}
}

func TestValidatePolicy_BadEffect(t *testing.T) {
	policy := `{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect":"Maybe","Principal":"*","Action":"s3:GetObject","Resource":"*"
      }]
    }`
	f := app.ValidatePolicy(policy)
	if !app.HasErrors(f) {
		t.Fatalf("expected error for bad Effect value, got %v", f)
	}
}

func TestValidatePolicy_SingleStatementObject(t *testing.T) {
	policy := `{
      "Version": "2012-10-17",
      "Statement": {
        "Effect":"Allow","Principal":"*",
        "Action":"s3:GetObject","Resource":"*"
      }
    }`
	f := app.ValidatePolicy(policy)
	if app.HasErrors(f) {
		t.Fatalf("expected single-statement-object to be valid, got %v", f)
	}
}
