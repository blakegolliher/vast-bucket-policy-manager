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

	return checkPolicyStructure(raw)
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

func checkPolicyStructure(p map[string]any) []Finding {
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
			out = append(out, checkStatement(obj, fmt.Sprintf("Statement[%d]", i))...)
		}
	case map[string]any:
		out = append(out, checkStatement(s, "Statement")...)
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

func checkStatement(s map[string]any, path string) []Finding {
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
		out = append(out, checkStringOrArray(s["Action"], path+".Action")...)
	}
	if hasNotAct {
		out = append(out, checkStringOrArray(s["NotAction"], path+".NotAction")...)
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
		out = append(out, checkStringOrArray(s["Resource"], path+".Resource")...)
	}
	if hasNotRes {
		out = append(out, checkStringOrArray(s["NotResource"], path+".NotResource")...)
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
