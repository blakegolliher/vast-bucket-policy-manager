package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Severity classifies a validation finding.
type Severity int

const (
	SevError Severity = iota
	SevWarning
)

func (s Severity) String() string {
	if s == SevError {
		return "ERROR"
	}
	return "WARN"
}

// Finding describes a single validation issue.
type Finding struct {
	Severity Severity
	Line     int // 1-based; 0 if unknown
	Col      int // 1-based; 0 if unknown
	Path     string
	Message  string
}

func (f Finding) String() string {
	loc := ""
	if f.Line > 0 {
		loc = fmt.Sprintf(" line %d:%d", f.Line, f.Col)
	}
	p := ""
	if f.Path != "" {
		p = " (" + f.Path + ")"
	}
	return fmt.Sprintf("%s%s%s: %s", f.Severity, loc, p, f.Message)
}

// ValidatePolicy runs JSON syntax + IAM structural checks on a bucket policy.
// Returns findings sorted with errors first.
func ValidatePolicy(src string) []Finding {
	return ValidatePolicyForBucket(src, "")
}

// ValidatePolicyForBucket is ValidatePolicy plus checks that depend on the
// bucket being edited: Resource ARNs must refer to that bucket. An empty
// bucket skips those checks.
func ValidatePolicyForBucket(src, bucket string) []Finding {
	src = strings.TrimSpace(src)
	if src == "" {
		return []Finding{{Severity: SevError, Message: "policy is empty"}}
	}

	if !json.Valid([]byte(src)) {
		line, col, msg := findJSONError(src)
		return []Finding{{Severity: SevError, Line: line, Col: col, Message: msg}}
	}

	var raw map[string]any
	if err := json.Unmarshal([]byte(src), &raw); err != nil {
		return []Finding{{Severity: SevError, Message: "policy must be a JSON object: " + err.Error()}}
	}

	return checkPolicyStructure(raw, bucket)
}

// findJSONError parses the source and pinpoints the byte offset of the syntax
// error, then converts it to a line/column.
func findJSONError(src string) (line, col int, msg string) {
	var v any
	err := json.Unmarshal([]byte(src), &v)
	if err == nil {
		return 0, 0, "unknown JSON error"
	}
	var se *json.SyntaxError
	if errors.As(err, &se) {
		line, col = offsetToLineCol(src, int(se.Offset))
		return line, col, "JSON syntax: " + se.Error()
	}
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		line, col = offsetToLineCol(src, int(te.Offset))
		return line, col, "JSON type error: " + te.Error()
	}
	return 0, 0, err.Error()
}

func offsetToLineCol(src string, off int) (int, int) {
	if off < 0 {
		off = 0
	}
	if off > len(src) {
		off = len(src)
	}
	line, col := 1, 1
	for i := 0; i < off; i++ {
		if src[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

func checkPolicyStructure(p map[string]any, bucket string) []Finding {
	var out []Finding

	if v, ok := p["Version"]; !ok {
		out = append(out, Finding{Severity: SevWarning, Path: "Version", Message: "missing; AWS recommends \"2012-10-17\""})
	} else if s, ok := v.(string); !ok {
		out = append(out, Finding{Severity: SevError, Path: "Version", Message: "must be a string"})
	} else if s != "2012-10-17" && s != "2008-10-17" {
		out = append(out, Finding{Severity: SevWarning, Path: "Version", Message: fmt.Sprintf("unexpected value %q; expected \"2012-10-17\"", s)})
	}

	stmtRaw, ok := p["Statement"]
	if !ok {
		out = append(out, Finding{Severity: SevError, Path: "Statement", Message: "missing"})
		return out
	}

	// Statement may be a single object or an array of objects.
	switch s := stmtRaw.(type) {
	case []any:
		if len(s) == 0 {
			out = append(out, Finding{Severity: SevError, Path: "Statement", Message: "empty array"})
		}
		for i, item := range s {
			obj, ok := item.(map[string]any)
			if !ok {
				out = append(out, Finding{Severity: SevError, Path: fmt.Sprintf("Statement[%d]", i), Message: "must be an object"})
				continue
			}
			out = append(out, checkStatement(obj, fmt.Sprintf("Statement[%d]", i), bucket)...)
		}
	case map[string]any:
		out = append(out, checkStatement(s, "Statement", bucket)...)
	default:
		out = append(out, Finding{Severity: SevError, Path: "Statement", Message: "must be an object or array of objects"})
	}

	// Catch unknown top-level keys.
	for k := range p {
		switch k {
		case "Version", "Id", "Statement":
		default:
			out = append(out, Finding{Severity: SevWarning, Path: k, Message: "unknown top-level key"})
		}
	}

	return out
}

func checkStatement(s map[string]any, path string, bucket string) []Finding {
	var out []Finding

	// Effect: required, must be Allow|Deny.
	eff, ok := s["Effect"]
	if !ok {
		out = append(out, Finding{Severity: SevError, Path: path + ".Effect", Message: "required"})
	} else if es, ok := eff.(string); !ok {
		out = append(out, Finding{Severity: SevError, Path: path + ".Effect", Message: "must be a string"})
	} else if es != "Allow" && es != "Deny" {
		out = append(out, Finding{Severity: SevError, Path: path + ".Effect", Message: fmt.Sprintf("must be \"Allow\" or \"Deny\", got %q", es)})
	}

	// Action vs NotAction: exactly one required.
	_, hasAct := s["Action"]
	_, hasNotAct := s["NotAction"]
	switch {
	case !hasAct && !hasNotAct:
		out = append(out, Finding{Severity: SevError, Path: path, Message: "must have Action or NotAction"})
	case hasAct && hasNotAct:
		out = append(out, Finding{Severity: SevError, Path: path, Message: "cannot have both Action and NotAction"})
	}
	if hasAct {
		out = append(out, checkActions(s["Action"], path+".Action")...)
	}
	if hasNotAct {
		out = append(out, checkActions(s["NotAction"], path+".NotAction")...)
	}

	// Resource vs NotResource: exactly one required for bucket policies.
	_, hasRes := s["Resource"]
	_, hasNotRes := s["NotResource"]
	switch {
	case !hasRes && !hasNotRes:
		out = append(out, Finding{Severity: SevError, Path: path, Message: "must have Resource or NotResource"})
	case hasRes && hasNotRes:
		out = append(out, Finding{Severity: SevError, Path: path, Message: "cannot have both Resource and NotResource"})
	}
	if hasRes {
		out = append(out, checkResources(s["Resource"], path+".Resource", bucket)...)
	}
	if hasNotRes {
		// NotResource semantics are inverted, so only check ARN shape, not
		// that it names the current bucket.
		out = append(out, checkResources(s["NotResource"], path+".NotResource", "")...)
	}

	// Principal vs NotPrincipal: required for bucket policies (resource-based).
	_, hasPrin := s["Principal"]
	_, hasNotPrin := s["NotPrincipal"]
	if !hasPrin && !hasNotPrin {
		out = append(out, Finding{Severity: SevWarning, Path: path, Message: "bucket policies (resource-based) should specify Principal or NotPrincipal"})
	}
	if hasPrin && hasNotPrin {
		out = append(out, Finding{Severity: SevError, Path: path, Message: "cannot have both Principal and NotPrincipal"})
	}
	if hasPrin {
		out = append(out, checkPrincipal(s["Principal"], path+".Principal")...)
	}
	if hasNotPrin {
		out = append(out, checkPrincipal(s["NotPrincipal"], path+".NotPrincipal")...)
	}

	// Condition: must be an object if present.
	if c, ok := s["Condition"]; ok {
		if _, ok := c.(map[string]any); !ok {
			out = append(out, Finding{Severity: SevError, Path: path + ".Condition", Message: "must be an object"})
		}
	}

	// Unknown keys.
	for k := range s {
		switch k {
		case "Sid", "Effect", "Action", "NotAction", "Resource", "NotResource",
			"Principal", "NotPrincipal", "Condition":
		default:
			out = append(out, Finding{Severity: SevWarning, Path: path + "." + k, Message: "unknown statement key"})
		}
	}

	return out
}

func checkStringOrArray(v any, path string) []Finding {
	switch t := v.(type) {
	case string:
		if t == "" {
			return []Finding{{Severity: SevError, Path: path, Message: "empty string"}}
		}
		return nil
	case []any:
		if len(t) == 0 {
			return []Finding{{Severity: SevError, Path: path, Message: "empty array"}}
		}
		var out []Finding
		for i, e := range t {
			s, ok := e.(string)
			if !ok {
				out = append(out, Finding{Severity: SevError, Path: fmt.Sprintf("%s[%d]", path, i), Message: "must be a string"})
				continue
			}
			if s == "" {
				out = append(out, Finding{Severity: SevError, Path: fmt.Sprintf("%s[%d]", path, i), Message: "empty string"})
			}
		}
		return out
	default:
		return []Finding{{Severity: SevError, Path: path, Message: "must be a string or array of strings"}}
	}
}

// s3ActionNames is the set of known S3 actions (lowercased, without the
// "s3:" prefix) for validating Action/NotAction entries.
var s3ActionNames = map[string]bool{
	"abortmultipartupload": true, "bypassgovernanceretention": true,
	"createbucket": true, "deletebucket": true, "deletebucketpolicy": true,
	"deletebucketwebsite": true, "deleteobject": true, "deleteobjecttagging": true,
	"deleteobjectversion": true, "deleteobjectversiontagging": true,
	"getaccelerateconfiguration": true, "getanalyticsconfiguration": true,
	"getbucketacl": true, "getbucketcors": true, "getbucketlocation": true,
	"getbucketlogging": true, "getbucketnotification": true,
	"getbucketobjectlockconfiguration": true, "getbucketownershipcontrols": true,
	"getbucketpolicy": true, "getbucketpolicystatus": true,
	"getbucketpublicaccessblock": true, "getbucketrequestpayment": true,
	"getbuckettagging": true, "getbucketversioning": true, "getbucketwebsite": true,
	"getencryptionconfiguration": true, "getintelligenttieringconfiguration": true,
	"getinventoryconfiguration": true, "getlifecycleconfiguration": true,
	"getmetricsconfiguration": true, "getobject": true, "getobjectacl": true,
	"getobjectattributes": true, "getobjectlegalhold": true,
	"getobjectretention": true, "getobjecttagging": true, "getobjecttorrent": true,
	"getobjectversion": true, "getobjectversionacl": true,
	"getobjectversionattributes": true, "getobjectversionforreplication": true,
	"getobjectversiontagging": true, "getobjectversiontorrent": true,
	"getreplicationconfiguration": true, "initiatereplication": true,
	"listallmybuckets": true, "listbucket": true, "listbucketmultipartuploads": true,
	"listbucketversions": true, "listmultipartuploadparts": true,
	"objectowneroverridetobucketowner": true, "putaccelerateconfiguration": true,
	"putanalyticsconfiguration": true, "putbucketacl": true, "putbucketcors": true,
	"putbucketlogging": true, "putbucketnotification": true,
	"putbucketobjectlockconfiguration": true, "putbucketownershipcontrols": true,
	"putbucketpolicy": true, "putbucketpublicaccessblock": true,
	"putbucketrequestpayment": true, "putbuckettagging": true,
	"putbucketversioning": true, "putbucketwebsite": true,
	"putencryptionconfiguration": true, "putintelligenttieringconfiguration": true,
	"putinventoryconfiguration": true, "putlifecycleconfiguration": true,
	"putmetricsconfiguration": true, "putobject": true, "putobjectacl": true,
	"putobjectlegalhold": true, "putobjectretention": true,
	"putobjecttagging": true, "putobjectversionacl": true,
	"putobjectversiontagging": true, "putreplicationconfiguration": true,
	"replicatedelete": true, "replicateobject": true, "replicatetags": true,
	"restoreobject": true,
}

// checkActions validates Action/NotAction values: shape, "s3:" prefix, and
// that the action name (after wildcard expansion) is a known S3 action.
func checkActions(v any, path string) []Finding {
	out := checkStringOrArray(v, path)
	forEachString(v, path, func(a, p string) {
		if a == "" || a == "*" {
			return
		}
		svc, name, ok := strings.Cut(a, ":")
		if !ok {
			out = append(out, Finding{Severity: SevError, Path: p, Message: fmt.Sprintf("%q is not a valid action; expected \"s3:ActionName\"", a)})
			return
		}
		if !strings.EqualFold(svc, "s3") {
			out = append(out, Finding{Severity: SevError, Path: p, Message: fmt.Sprintf("%q: bucket policies only support s3: actions", a)})
			return
		}
		if !knownS3Action(name) {
			out = append(out, Finding{Severity: SevError, Path: p, Message: fmt.Sprintf("unknown S3 action %q", a)})
		}
	})
	return out
}

// knownS3Action reports whether name (which may contain * and ? wildcards)
// matches at least one known S3 action. Matching is case-insensitive, like IAM.
func knownS3Action(name string) bool {
	name = strings.ToLower(name)
	if !strings.ContainsAny(name, "*?") {
		return s3ActionNames[name]
	}
	for known := range s3ActionNames {
		if wildcardMatch(name, known) {
			return true
		}
	}
	return false
}

// checkResources validates Resource/NotResource values: shape, S3 ARN format,
// and (when bucket is non-empty) that the ARN refers to that bucket.
func checkResources(v any, path, bucket string) []Finding {
	const arnPrefix = "arn:aws:s3:::"
	out := checkStringOrArray(v, path)
	forEachString(v, path, func(r, p string) {
		if r == "" {
			return
		}
		if !strings.HasPrefix(r, arnPrefix) || r == arnPrefix {
			out = append(out, Finding{Severity: SevError, Path: p, Message: fmt.Sprintf("%q is not an S3 ARN; expected \"arn:aws:s3:::bucket\" or \"arn:aws:s3:::bucket/key\"", r)})
			return
		}
		if bucket == "" {
			return
		}
		resBucket, _, _ := strings.Cut(strings.TrimPrefix(r, arnPrefix), "/")
		if !wildcardMatch(resBucket, bucket) {
			out = append(out, Finding{Severity: SevError, Path: p, Message: fmt.Sprintf("resource names bucket %q but this policy is for bucket %q", resBucket, bucket)})
		}
	})
	return out
}

// forEachString calls fn for each string in a string-or-array value, with the
// element's path. Shape errors are left to checkStringOrArray.
func forEachString(v any, path string, fn func(s, path string)) {
	switch t := v.(type) {
	case string:
		fn(t, path)
	case []any:
		for i, e := range t {
			if s, ok := e.(string); ok {
				fn(s, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
}

// wildcardMatch reports whether s matches pattern, where '*' matches any run
// of characters and '?' matches exactly one.
func wildcardMatch(pattern, s string) bool {
	pi, si := 0, 0
	star, starSi := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star, starSi = pi, si
			pi++
		case star >= 0:
			starSi++
			pi, si = star+1, starSi
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func checkPrincipal(v any, path string) []Finding {
	switch t := v.(type) {
	case string:
		// Only "*" is valid as a string principal.
		if t != "*" {
			return []Finding{{Severity: SevError, Path: path, Message: "string principal must be \"*\""}}
		}
		return nil
	case map[string]any:
		if len(t) == 0 {
			return []Finding{{Severity: SevError, Path: path, Message: "empty object"}}
		}
		var out []Finding
		for k, val := range t {
			switch k {
			case "AWS", "Service", "Federated", "CanonicalUser":
				out = append(out, checkStringOrArray(val, path+"."+k)...)
			default:
				out = append(out, Finding{Severity: SevWarning, Path: path + "." + k, Message: "unknown principal type"})
			}
		}
		return out
	default:
		return []Finding{{Severity: SevError, Path: path, Message: "must be \"*\" or an object"}}
	}
}

// HasErrors returns true if any finding is at error severity.
func HasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == SevError {
			return true
		}
	}
	return false
}

// PrettyJSON re-indents the JSON for display. Returns the input unchanged if
// it isn't valid JSON.
func PrettyJSON(src string) string {
	var v any
	if err := json.Unmarshal([]byte(src), &v); err != nil {
		return src
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return src
	}
	return string(out)
}
