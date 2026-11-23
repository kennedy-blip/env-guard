package handler

import (
	"encoding/json"
	"net/http"
	"strings"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch {
	case r.URL.Path == "/api/health":
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "engine": "EnvGuard Go Engine", "version": "1.0.0"})
	case r.URL.Path == "/api/templates" && r.Method == http.MethodGet:
		TemplatesHandler(w, r)
	case r.URL.Path == "/api/templates" && r.Method == http.MethodPost:
		SaveTemplateHandler(w, r)
	case r.URL.Path == "/api/validate" && r.Method == http.MethodPost:
		ValidateHandler(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/"):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "API route not found"})
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
