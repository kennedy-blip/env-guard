package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

type Rule struct {
	Key      string   `json:"key"`
	Format   string   `json:"format"`
	Min      int      `json:"min,omitempty"`
	Max      int      `json:"max,omitempty"`
	Allowed  []string `json:"allowed,omitempty"`
	Required bool     `json:"required,omitempty"`
}

type Template struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	TargetEnv   string   `json:"targetEnv"`
	RequiredKeys []string `json:"requiredKeys"`
	Rules       []Rule   `json:"rules"`
	RawEnvText  string   `json:"rawEnvText"`
}

var templateStore = struct {
	sync.RWMutex
	items []Template
}{items: []Template{
	{
		ID: "payments-production", Name: "Payments & Webhook Gateway (production)", TargetEnv: "production",
		RequiredKeys: []string{"APP_ENV", "APP_URL", "DATABASE_URL", "PAYMENT_SECRET", "PORT", "DEBUG"},
		Rules: []Rule{{Key:"APP_ENV", Format:"ENUM", Allowed:[]string{"production"}}, {Key:"APP_URL", Format:"URL_HTTPS"}, {Key:"DATABASE_URL", Format:"POSTGRES_DSN"}, {Key:"PAYMENT_SECRET", Format:"SECRET_MIN_LEN", Min:32}, {Key:"PORT", Format:"INTEGER_RANGE", Min:1, Max:65535}, {Key:"DEBUG", Format:"ENUM", Allowed:[]string{"false"}}},
		RawEnvText: "APP_ENV=production\nAPP_URL=https://api.example.com\nDATABASE_URL=postgres://app:replace-me@db.example.com:5432/payments?sslmode=require\nPAYMENT_SECRET=replace-with-a-strong-random-secret-value\nPORT=8080\nDEBUG=false",
	},
	{
		ID: "analytics-staging", Name: "Analytics & Data Worker (staging)", TargetEnv: "staging",
		RequiredKeys: []string{"APP_ENV", "DATABASE_URL", "REDIS_URL", "WORKER_CONCURRENCY"},
		Rules: []Rule{{Key:"APP_ENV", Format:"ENUM", Allowed:[]string{"staging"}}, {Key:"DATABASE_URL", Format:"POSTGRES_DSN"}, {Key:"REDIS_URL", Format:"URL"}, {Key:"WORKER_CONCURRENCY", Format:"INTEGER_RANGE", Min:1, Max:64}},
		RawEnvText: "APP_ENV=staging\nDATABASE_URL=postgres://worker:replace-me@staging-db.example.com:5432/analytics\nREDIS_URL=redis://cache.example.com:6379/0\nWORKER_CONCURRENCY=4",
	},
	{
		ID: "local-dev", Name: "Local Dev API Service (development)", TargetEnv: "development",
		RequiredKeys: []string{"APP_ENV", "APP_URL", "DATABASE_URL", "DEBUG", "PORT"},
		Rules: []Rule{{Key:"APP_ENV", Format:"ENUM", Allowed:[]string{"development"}}, {Key:"APP_URL", Format:"URL"}, {Key:"DATABASE_URL", Format:"POSTGRES_DSN"}, {Key:"DEBUG", Format:"ENUM", Allowed:[]string{"true","false"}}, {Key:"PORT", Format:"INTEGER_RANGE", Min:1, Max:65535}},
		RawEnvText: "APP_ENV=development\nAPP_URL=http://localhost:3000\nDATABASE_URL=postgres://dev:dev@localhost:5432/app\nDEBUG=true\nPORT=3000",
	},
}}

func TemplatesHandler(w http.ResponseWriter, r *http.Request) {
	templateStore.RLock()
	defer templateStore.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"templates": templateStore.items})
}

func SaveTemplateHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	var item Template
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}
	item.ID = strings.TrimSpace(item.ID)
	item.Name = strings.TrimSpace(item.Name)
	item.TargetEnv = strings.ToLower(strings.TrimSpace(item.TargetEnv))
	if item.Name == "" || !validEnvironment(item.TargetEnv) || len(item.Rules) > 200 || len(item.RequiredKeys) > 200 || len(item.RawEnvText) > 100000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Provide a name, valid targetEnv, and a contract within the size limits"})
		return
	}
	if item.ID == "" {
		item.ID = "custom-" + strings.ToLower(strings.ReplaceAll(item.Name, " ", "-"))
	}
	templateStore.Lock()
	defer templateStore.Unlock()
	for i := range templateStore.items {
		if templateStore.items[i].ID == item.ID {
			templateStore.items[i] = item
			writeJSON(w, http.StatusOK, map[string]any{"template": item, "message": "Contract updated in this server instance"})
			return
		}
	}
	templateStore.items = append(templateStore.items, item)
	writeJSON(w, http.StatusCreated, map[string]any{"template": item, "message": "Contract saved in this server instance"})
}
