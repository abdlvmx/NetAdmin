package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

func TestKindByExt(t *testing.T) {
	cases := map[string]string{
		"7zip.msi": "msi", "setup.EXE": "exe", "deploy.ps1": "script",
		"run.bat": "script", "x.cmd": "script", "noext": "exe",
	}
	for name, want := range cases {
		if got := kindByExt(name); got != want {
			t.Errorf("kindByExt(%q)=%q, ожидалось %q", name, got, want)
		}
	}
}

func TestPackagesPageRenders(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "packages", packagesData{
		User: &auth.User{ID: 1, Username: "admin", Role: "admin"}, Active: "packages",
		Packages: []pkgRow{{ID: 1, Name: "7-Zip", Original: "7z.msi", Kind: "msi", SizeMB: "1.5 МБ", Created: "01.01 10:00"}},
		Devices:  []employeeOpt{{ID: 1, Name: "WS-1"}},
		Recent:   []deployRow{{Device: "WS-1", Package: "Установка: 7-Zip", Status: "done", Result: "ok", Created: "01.01 10:05"}},
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона: %s", body)
	}
	if !strings.Contains(body, "Загрузить дистрибутив") {
		t.Fatal("в выводе нет формы загрузки")
	}
}
