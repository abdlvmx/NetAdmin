package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"

	"netadmin/internal/auth"
	"netadmin/internal/config"
	"netadmin/internal/diagnostics"
	"netadmin/internal/version"
	"netadmin/internal/web"
)

const maxDiagnosticConfigBytes = 64 << 10

type diagnosticsData struct {
	User   *auth.User
	Active string
	Report diagnostics.Report
}

// readDiagnosticConfig never calls config.Load: diagnostics must not generate
// credentials or save default settings when the file is missing or malformed.
// The decoder discards all fields other than this explicit allowlist.
func readDiagnosticConfig() (config.Config, string) {
	ctx, cancel := context.WithTimeout(context.Background(), diagnostics.Timeout)
	defer cancel()
	return readDiagnosticConfigContext(ctx)
}

type diagnosticConfigResult struct {
	config config.Config
	state  string
}

func readDiagnosticConfigContext(ctx context.Context) (config.Config, string) {
	path := config.ConfigPath()
	result, err := diagnostics.Filesystem(ctx, func() (diagnosticConfigResult, error) {
		cfg, state := readDiagnosticConfigFile(ctx, path)
		return diagnosticConfigResult{config: cfg, state: state}, nil
	})
	if err != nil {
		if errors.Is(err, diagnostics.ErrFilesystemBusy) {
			return config.Config{}, diagnostics.ConfigBusy
		}
		if errors.Is(err, diagnostics.ErrFilesystemTimeout) {
			return config.Config{}, diagnostics.ConfigTimeout
		}
		return config.Config{}, diagnostics.ConfigUnavailable
	}
	return result.config, result.state
}

func readDiagnosticConfigFile(ctx context.Context, path string) (config.Config, string) {
	var allowed struct {
		ListenAddr          string `json:"listen_addr"`
		AllowSubnets        string `json:"allow_subnets"`
		BackupIntervalHours int    `json:"backup_interval_hours"`
		BackupKeep          int    `json:"backup_keep"`
		BackupDir           string `json:"backup_dir"`
	}
	if ctx.Err() != nil {
		return config.Config{}, diagnostics.ConfigTimeout
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config.Config{BackupIntervalHours: 24, BackupKeep: 7}, diagnostics.ConfigMissing
		}
		return config.Config{}, diagnostics.ConfigUnavailable
	}
	defer f.Close()
	if ctx.Err() != nil {
		return config.Config{}, diagnostics.ConfigTimeout
	}
	b, err := io.ReadAll(io.LimitReader(f, maxDiagnosticConfigBytes+1))
	if err != nil {
		return config.Config{}, diagnostics.ConfigUnavailable
	}
	trimmed := bytes.TrimSpace(b)
	if len(b) > maxDiagnosticConfigBytes || len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(b, &allowed) != nil {
		return config.Config{}, diagnostics.ConfigInvalid
	}
	cfg := config.Config{ListenAddr: allowed.ListenAddr, AllowSubnets: allowed.AllowSubnets,
		BackupIntervalHours: allowed.BackupIntervalHours, BackupKeep: allowed.BackupKeep, BackupDir: allowed.BackupDir}
	if cfg.BackupIntervalHours == 0 && cfg.BackupKeep == 0 {
		cfg.BackupIntervalHours, cfg.BackupKeep = 24, 7
	}
	return cfg, diagnostics.ConfigOK
}

func (a *App) diagnosticReport(r *http.Request) diagnostics.Report {
	ctx, cancel := context.WithTimeout(r.Context(), diagnostics.Timeout)
	defer cancel()
	cfg, state := readDiagnosticConfigContext(ctx)
	return diagnostics.Collect(ctx, diagnostics.Input{DB: a.DB, Version: version.Value, ConfigState: state,
		Listen: cfg.ListenAddrSetting(), Allow: cfg.AllowSubnetsSetting(), DataDir: config.DataDir(), DBPath: config.DBPath(),
		BackupDir: cfg.BackupDir, BackupIntervalHours: cfg.BackupIntervalHours, IsService: a.IsService, Demo: a.Demo})
}

// DiagnosticsPage — GET /settings/diagnostics; details are administrator-only.
func (a *App) DiagnosticsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.DB == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	u := auth.CurrentUser(a.DB, r)
	if !u.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	web.RenderPage(w, "diagnostics", diagnosticsData{User: u, Active: "settings", Report: a.diagnosticReport(r)})
}

// DiagnosticsArchive — GET /api/diagnostics/archive; builds in memory, never
// reads arbitrary request paths or raw logs, and never sends the result elsewhere.
func (a *App) DiagnosticsArchive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.DB == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	u := auth.CurrentUser(a.DB, r)
	if !u.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	report := a.diagnosticReport(r)
	b, err := diagnostics.Archive(report)
	if err != nil {
		http.Error(w, "Не удалось подготовить архив диагностики. Повторите попытку.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="NetAdmin-diagnostics-`+report.Summary.CreatedAt.Format("20060102-150405")+`.zip"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(b)
}
