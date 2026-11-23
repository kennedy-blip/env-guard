package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

type ValidationRequest struct {
	TargetEnv    string   `json:"targetEnv"`
	RawEnvText   string   `json:"rawEnvText"`
	RequiredKeys []string `json:"requiredKeys"`
	Rules        []Rule   `json:"rules"`
}

type Finding struct {
	Key        string `json:"key"`
	Masked     string `json:"masked"`
	Severity   string `json:"severity"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion"`
}

type parsedEntry struct {
	value string
}

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var postgresPattern = regexp.MustCompile(`^postgres(ql)?://`)

func ValidateHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 512*1024)
	var req ValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload or request exceeds 512 KB"})
		return
	}
	req.TargetEnv = strings.ToLower(strings.TrimSpace(req.TargetEnv))
	if !validEnvironment(req.TargetEnv) || len(req.RawEnvText) > 400000 || len(req.RequiredKeys) > 500 || len(req.Rules) > 500 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid environment or input exceeds validation limits"})
		return
	}
	entries := parseEnv(req.RawEnvText)
	ruleByKey := make(map[string]Rule, len(req.Rules))
	for _, rule := range req.Rules {
		if envKeyPattern.MatchString(rule.Key) {
			ruleByKey[rule.Key] = rule
		}
	}
	findings := make([]Finding, 0, len(entries)+len(req.RequiredKeys))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, key := range req.RequiredKeys {
		if _, ok := entries[key]; !ok {
			findings = append(findings, Finding{Key:key, Severity:"FAIL", Code:"MISSING_REQUIRED", Message:"Required variable is missing.", Suggestion:"Add this key to the environment bundle."})
		}
	}
	for key, entry := range entries {
		key, entry := key, entry
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := inspectValue(key, entry.value, req.TargetEnv, ruleByKey[key])
			mu.Lock()
			findings = append(findings, f)
			mu.Unlock()
		}()
	}
	wg.Wait()
	known := make(map[string]bool, len(req.RequiredKeys)+len(req.Rules))
	for _, key := range req.RequiredKeys { known[key] = true }
	for _, rule := range req.Rules { known[rule.Key] = true }
	for key, entry := range entries {
		if !known[key] {
			findings = append(findings, Finding{Key:key, Masked:maskValue(entry.value), Severity:"WARN", Code:"UNDECLARED_KEY", Message:"Variable is not declared in this contract.", Suggestion:"Add it to the contract or remove it if unused."})
		}
	}
	score := 100
	for _, f := range findings {
		switch f.Severity {
		case "FAIL": score -= 18
		case "WARN": score -= 7
		}
	}
	if score < 0 { score = 0 }
	verdict := "READY"
	if score < 60 { verdict = "BLOCKED" } else if score < 90 { verdict = "WARN" }
	writeJSON(w, http.StatusOK, map[string]any{"score":score, "verdict":verdict, "findings":findings, "checkedKeys":len(entries), "targetEnv":req.TargetEnv})
}

func parseEnv(raw string) map[string]parsedEntry {
	out := make(map[string]parsedEntry)
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "export ") { line = strings.TrimPrefix(line, "export "); if line == "" || strings.HasPrefix(line, "#") { continue } }
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 { continue }
		key := strings.TrimSpace(parts[0])
		if !envKeyPattern.MatchString(key) { continue }
		value := strings.TrimSpace(parts[1])
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) { value = value[1:len(value)-1] }
		out[key] = parsedEntry{value:value}
	}
	return out
}

func inspectValue(key, value, target string, rule Rule) Finding {
	f := Finding{Key:key, Masked:maskValue(value), Severity:"PASS", Code:"PASS", Message:"Value passed configured checks.", Suggestion:"No action required."}
	upper := strings.ToUpper(value)
	if isWeakSecret(key, value) {
		f.Severity, f.Code, f.Message, f.Suggestion = "FAIL", "WEAK_OR_PLACEHOLDER_SECRET", "Secret appears short, predictable, or is a placeholder.", "Use a unique randomly generated secret stored in a secret manager."
		return f
	}
	if target == "production" && (strings.EqualFold(value,"true") && (key == "DEBUG" || strings.HasPrefix(key,"ENABLE_")) || strings.Contains(strings.ToLower(value), "localhost") || strings.Contains(strings.ToLower(value), "127.0.0.1")) {
		f.Severity, f.Code, f.Message, f.Suggestion = "FAIL", "ENV_MISMATCH", "Development-only value detected in production.", "Use the production endpoint and disable debug-only flags."
		return f
	}
	switch rule.Format {
	case "URL_HTTPS", "URL":
		u, err := url.ParseRequestURI(value)
		if err != nil || u.Host == "" || (rule.Format == "URL_HTTPS" && u.Scheme != "https") || (u.Scheme != "http" && u.Scheme != "https") {
			f.Severity, f.Code, f.Message, f.Suggestion = "FAIL", "INVALID_URL_OR_DSN", "URL is malformed or does not use the required scheme.", "Provide a valid URL; use HTTPS for production endpoints."
		}
	case "POSTGRES_DSN":
		u, err := url.Parse(value)
		if err != nil || !postgresPattern.MatchString(value) || u.Host == "" || u.User == nil {
			f.Severity, f.Code, f.Message, f.Suggestion = "FAIL", "INVALID_URL_OR_DSN", "PostgreSQL connection string is malformed.", "Use postgres://user:password@host:5432/database."
		}
	case "INTEGER_RANGE":
		n, err := strconv.Atoi(value)
		if err != nil || n < rule.Min || n > rule.Max {
			f.Severity, f.Code, f.Message, f.Suggestion = "FAIL", "OUT_OF_RANGE_INT", fmt.Sprintf("Expected an integer from %d to %d.", rule.Min, rule.Max), "Set a numeric value within the contract range."
		}
	case "SECRET_MIN_LEN":
		if len([]rune(value)) < rule.Min {
			f.Severity, f.Code, f.Message, f.Suggestion = "FAIL", "WEAK_OR_PLACEHOLDER_SECRET", "Secret does not meet the minimum length.", "Generate a longer random secret; do not reuse credentials."
		}
	case "ENUM":
		found := false
		for _, allowed := range rule.Allowed { if value == allowed { found = true; break } }
		if len(rule.Allowed) > 0 && !found {
			f.Severity, f.Code, f.Message, f.Suggestion = "FAIL", "ENV_MISMATCH", "Value is not one of the contract's allowed options.", "Choose one of the declared values."
		}
	}
	_ = upper
	return f
}

func isWeakSecret(key, value string) bool {
	name := strings.ToUpper(key)
	if !(strings.Contains(name,"SECRET") || strings.Contains(name,"TOKEN") || strings.Contains(name,"PASSWORD") || strings.Contains(name,"API_KEY") || strings.Contains(name,"PRIVATE_KEY")) { return false }
	lower := strings.ToLower(strings.TrimSpace(value))
	if len([]rune(value)) < 16 || lower == "" { return true }
	for _, marker := range []string{"changeme","replace-me","replace_with","your_","example","placeholder","password","secret"} {
		if strings.Contains(lower, marker) { return true }
	}
	return false
}

func maskValue(value string) string {
	runes := []rune(value)
	if len(runes) == 0 { return "(empty)" }
	if len(runes) <= 4 { return strings.Repeat("*", len(runes)) }
	prefix := string(runes[:2])
	suffix := string(runes[len(runes)-4:])
	for _, r := range runes { if unicode.IsSpace(r) { return "[masked]" } }
	return prefix + strings.Repeat("*", minInt(len(runes)-6, 12)) + suffix
}

func validEnvironment(env string) bool {
	return env == "development" || env == "staging" || env == "production"
}

func minInt(a, b int) int {
	if a < b { return a }
	return b
}
