package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

func TestCmdByKey(t *testing.T) {
	if _, ok := cmdByKey("flushdns"); !ok {
		t.Fatal("flushdns должна быть в библиотеке")
	}
	if _, ok := cmdByKey("rm -rf /"); ok {
		t.Fatal("произвольная команда не должна находиться в библиотеке")
	}
	// все ключи библиотеки непустые и уникальные
	seen := map[string]bool{}
	for _, c := range commandLibrary {
		if c.Key == "" || c.Name == "" {
			t.Fatalf("пустой ключ/имя в библиотеке: %+v", c)
		}
		if seen[c.Key] {
			t.Fatalf("дубль ключа: %s", c.Key)
		}
		seen[c.Key] = true
	}
}

func TestCommandsPageRenders(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "commands", commandsData{
		User: &auth.User{ID: 1, Username: "admin", Role: "admin"}, Active: "commands",
		Library: commandLibrary,
		Devices: []employeeOpt{{ID: 1, Name: "WS-1"}},
		Recent:  []cmdRunRow{{Device: "WS-1", Command: "Команда: Очистить кэш DNS", Status: "done", Result: "ok", Created: "01.01 10:00"}},
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона: %s", body)
	}
	if !strings.Contains(body, "Запустить команду") {
		t.Fatal("в выводе нет формы запуска")
	}
}
