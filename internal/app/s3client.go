package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"gopkg.in/ini.v1"
)

// Connection holds the user-supplied parameters needed to build an S3 client.
type Connection struct {
	Profile     string // optional; if set, credentials are loaded from the shared config
	Endpoint    string // required; e.g. https://s3.vast.example.com
	AccessKey   string
	SecretKey   string
	Region      string // defaults to us-east-1
	InsecureTLS bool   // skip TLS verification — common for VAST clusters with self-signed certs
}

// Trim normalizes the user input.
func (c Connection) Trim() Connection {
	return Connection{
		Profile:     strings.TrimSpace(c.Profile),
		Endpoint:    strings.TrimSpace(c.Endpoint),
		AccessKey:   strings.TrimSpace(c.AccessKey),
		SecretKey:   strings.TrimSpace(c.SecretKey),
		Region:      strings.TrimSpace(c.Region),
		InsecureTLS: c.InsecureTLS,
	}
}

// Client wraps an S3 client with the operations the TUI needs.
type Client struct {
	s3       *s3.Client
	endpoint string
}

// Endpoint returns the base S3 endpoint this client was configured for. Used
// to scope on-disk backups.
func (c *Client) Endpoint() string { return c.endpoint }

// NewClient builds an S3 client suitable for VAST or any S3-compatible store.
func NewClient(ctx context.Context, c Connection) (*Client, error) {
	c = c.Trim()
	if c.Endpoint == "" {
		return nil, errors.New("endpoint is required")
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}

	var loadOpts []func(*awsconfig.LoadOptions) error
	loadOpts = append(loadOpts, awsconfig.WithRegion(c.Region))

	if c.InsecureTLS {
		httpClient := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{}
			}
			tr.TLSClientConfig.InsecureSkipVerify = true
		})
		loadOpts = append(loadOpts, awsconfig.WithHTTPClient(httpClient))
	}

	// Profile takes priority: if set, let the SDK read everything (creds,
	// region, endpoint_url, etc.) from the shared config files. Manual
	// access/secret only kicks in when no profile is given.
	switch {
	case c.Profile != "":
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(c.Profile))
	case c.AccessKey != "" && c.SecretKey != "":
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey, ""),
		))
	default:
		return nil, errors.New("provide either an AWS profile or access key + secret key")
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	s3c := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
		}
		o.UsePathStyle = true // VAST and most non-AWS S3 stores want path style
	})
	return &Client{s3: s3c, endpoint: c.Endpoint}, nil
}

// ProfileData are the fields we surface in the UI when the user picks an AWS
// profile, read from the shared config and credentials files.
type ProfileData struct {
	Region      string
	Endpoint    string
	AccessKey   string
	SecretKey   string
}

// LoadProfileData reads a named profile from ~/.aws/{credentials,config}.
// Missing files or sections are not an error — the returned struct's empty
// fields signal "not set."
func LoadProfileData(name string) ProfileData {
	var pd ProfileData
	if name == "" {
		return pd
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return pd
	}

	// ~/.aws/credentials: plain section names, no "profile " prefix.
	if f, err := ini.Load(filepath.Join(home, ".aws", "credentials")); err == nil {
		if s, err := f.GetSection(name); err == nil {
			pd.AccessKey = s.Key("aws_access_key_id").String()
			pd.SecretKey = s.Key("aws_secret_access_key").String()
			pd.Region = s.Key("region").String()
		}
	}

	// ~/.aws/config: section is "profile foo" except for "default".
	if f, err := ini.Load(filepath.Join(home, ".aws", "config")); err == nil {
		secName := "profile " + name
		if name == "default" {
			secName = "default"
		}
		if s, err := f.GetSection(secName); err == nil {
			if v := s.Key("region").String(); v != "" {
				pd.Region = v
			}
			if v := s.Key("endpoint_url").String(); v != "" {
				pd.Endpoint = v
			}
			// Some users put S3-specific endpoints under s3.endpoint_url.
			if pd.Endpoint == "" {
				if v := s.Key("s3.endpoint_url").String(); v != "" {
					pd.Endpoint = v
				}
			}
		}
	}
	return pd
}

// ListBuckets returns the names of buckets visible to the authenticated user.
func (c *Client) ListBuckets(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, prettyAWSErr(err)
	}
	names := make([]string, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		if b.Name != nil {
			names = append(names, *b.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// GetBucketPolicy returns the policy JSON for a bucket. An empty string is
// returned if the bucket has no policy set (NoSuchBucketPolicy).
func (c *Client) GetBucketPolicy(ctx context.Context, bucket string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := c.s3.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(bucket)})
	if err != nil {
		if isNoSuchPolicy(err) {
			return "", nil
		}
		return "", prettyAWSErr(err)
	}
	if out.Policy == nil {
		return "", nil
	}
	return *out.Policy, nil
}

// PutBucketPolicy uploads a policy JSON to a bucket.
func (c *Client) PutBucketPolicy(ctx context.Context, bucket, policy string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := c.s3.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucket),
		Policy: aws.String(policy),
	})
	if err != nil {
		return prettyAWSErr(err)
	}
	return nil
}

// DeleteBucketPolicy removes the policy on a bucket.
func (c *Client) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := c.s3.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: aws.String(bucket)})
	if err != nil {
		return prettyAWSErr(err)
	}
	return nil
}

func isNoSuchPolicy(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode() == "NoSuchBucketPolicy"
	}
	return false
}

// prettyAWSErr unwraps an AWS SDK error to its underlying API code + message
// where possible, so the user sees something readable.
func prettyAWSErr(err error) error {
	if err == nil {
		return nil
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return fmt.Errorf("%s: %s", ae.ErrorCode(), ae.ErrorMessage())
	}
	return err
}

// DiscoverProfiles returns the names of profiles defined in the user's shared
// AWS credentials and config files. Returns an empty slice if neither exists.
func DiscoverProfiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	add := func(path string, configFile bool) {
		f, err := ini.Load(path)
		if err != nil {
			return
		}
		for _, s := range f.Sections() {
			name := s.Name()
			if name == ini.DefaultSection {
				continue
			}
			// In ~/.aws/config, section names are "profile foo" except for "default".
			if configFile && strings.HasPrefix(name, "profile ") {
				name = strings.TrimPrefix(name, "profile ")
			}
			seen[name] = struct{}{}
		}
	}
	add(filepath.Join(home, ".aws", "credentials"), false)
	add(filepath.Join(home, ".aws", "config"), true)

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
