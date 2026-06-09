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
        "Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*"
      }
    }`
	f := app.ValidatePolicy(policy)
	if app.HasErrors(f) {
		t.Fatalf("expected single-statement-object to be valid, got %v", f)
	}
}

func TestValidatePolicy_UnknownAction(t *testing.T) {
	policy := `{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect":"Allow","Principal":"*",
        "Action":"s3:NotAReal","Resource":"arn:aws:s3:::mybucket/*"
      }]
    }`
	f := app.ValidatePolicy(policy)
	if !app.HasErrors(f) {
		t.Fatalf("expected error for unknown action s3:NotAReal, got %v", f)
	}
}

func TestValidatePolicy_ActionWildcards(t *testing.T) {
	for _, a := range []string{"*", "s3:*", "s3:Get*", "s3:GETOBJECT"} {
		policy := `{
          "Version": "2012-10-17",
          "Statement": [{
            "Effect":"Allow","Principal":"*",
            "Action":"` + a + `","Resource":"arn:aws:s3:::mybucket/*"
          }]
        }`
		if f := app.ValidatePolicy(policy); app.HasErrors(f) {
			t.Errorf("action %q: expected no errors, got %v", a, f)
		}
	}
	// A wildcard that matches no known action is still an error.
	policy := `{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect":"Allow","Principal":"*",
        "Action":"s3:NotAReal*","Resource":"arn:aws:s3:::mybucket/*"
      }]
    }`
	if f := app.ValidatePolicy(policy); !app.HasErrors(f) {
		t.Errorf("expected error for s3:NotAReal*, got %v", f)
	}
}

func TestValidatePolicy_NonS3Action(t *testing.T) {
	policy := `{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect":"Allow","Principal":"*",
        "Action":"iam:PassRole","Resource":"arn:aws:s3:::mybucket/*"
      }]
    }`
	f := app.ValidatePolicy(policy)
	if !app.HasErrors(f) {
		t.Fatalf("expected error for non-s3 action, got %v", f)
	}
}

func TestValidatePolicy_BadResourceARN(t *testing.T) {
	for _, r := range []string{"*", "mybucket", "arn:aws:s3:::"} {
		policy := `{
          "Version": "2012-10-17",
          "Statement": [{
            "Effect":"Allow","Principal":"*",
            "Action":"s3:GetObject","Resource":"` + r + `"
          }]
        }`
		if f := app.ValidatePolicy(policy); !app.HasErrors(f) {
			t.Errorf("resource %q: expected ARN format error, got %v", r, f)
		}
	}
}

func TestValidatePolicyForBucket_ResourceMismatch(t *testing.T) {
	policy := `{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect":"Allow","Principal":"*",
        "Action":"s3:GetObject",
        "Resource":["arn:aws:s3:::otherbucket","arn:aws:s3:::otherbucket/*"]
      }]
    }`
	f := app.ValidatePolicyForBucket(policy, "mybucket")
	if !app.HasErrors(f) {
		t.Fatalf("expected errors for resource bucket mismatch, got %v", f)
	}
	// Same policy validated without a bucket context is fine.
	if f := app.ValidatePolicy(policy); app.HasErrors(f) {
		t.Fatalf("expected no errors without bucket context, got %v", f)
	}
}

func TestValidatePolicyForBucket_ResourceMatch(t *testing.T) {
	policy := `{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect":"Allow","Principal":"*",
        "Action":"s3:GetObject",
        "Resource":["arn:aws:s3:::mybucket","arn:aws:s3:::mybucket/*","arn:aws:s3:::my*"]
      }]
    }`
	f := app.ValidatePolicyForBucket(policy, "mybucket")
	if app.HasErrors(f) {
		t.Fatalf("expected no errors for matching bucket, got %v", f)
	}
}
