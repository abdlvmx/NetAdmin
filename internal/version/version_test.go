package version

import (
	"os"
	"strings"
	"testing"
)

func TestFormat(t *testing.T) {
	rev := "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
	cases := []struct {
		name  string
		build Build
		ok    bool
		want  string
	}{
		{"без сведений о сборке", Build{}, false, "1.2.0"},
		{"из репозитория", Build{Revision: rev}, true, "1.2.0 · a1b2c3d"},
		{"с правками в дереве", Build{Revision: rev, Modified: true}, true,
			"1.2.0 · a1b2c3d (с правками)"},
		{"короткая ревизия целиком", Build{Revision: "abc"}, true, "1.2.0 · abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := format("1.2.0", c.build, c.ok); got != c.want {
				t.Errorf("format = %q, ожидалось %q", got, c.want)
			}
		})
	}
}

// Номер версии обязан присутствовать в строке всегда: остальное — уточнения,
// а на вопрос «какая у вас версия» отвечает именно он.
func TestFullContainsValue(t *testing.T) {
	if !strings.Contains(Full(), Value) {
		t.Errorf("Full() = %q, номера версии %q в ней нет", Full(), Value)
	}
}

// Рабочий процесс релиза обязан проставлять номер из тега.
//
// Без ключа -X оба файла уехали бы со значением по умолчанию, и релиз v1.2.0
// называл бы себя предыдущей версией — молча и во всех местах сразу: в
// «Настройках», в выводе -version, в журнале службы и в heartbeat агента.
// Заметить это можно только глазами и только после выпуска.
func TestReleaseStampsVersion(t *testing.T) {
	b, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Skipf("release.yml не найден: %v", err)
	}
	yml := string(b)
	b, err = os.ReadFile("../../scripts/build-windows.ps1")
	if err != nil {
		t.Fatalf("Windows build helper не найден: %v", err)
	}
	helper := string(b)
	if !strings.Contains(yml, "$ver = $env:RELEASE_TAG -replace '^v', ''") ||
		!strings.Contains(yml, "./scripts/build-windows.ps1 -Version $ver -Edition all") {
		t.Fatal("release.yml должен передавать версию из тега сборщику обеих редакций")
	}

	// Полный путь символа: при переименовании пакета ключ -X молча перестаёт
	// что-либо задавать — линковщик о промахе не сообщает.
	const symbol = "-X netadmin/internal/version.Value="
	if !strings.Contains(helper, symbol+"$Version") {
		t.Fatalf("в build-windows.ps1 нет %q с переданной версией — релиз уйдёт с версией по умолчанию (%s)",
			symbol, Value)
	}

	// Оба бинарника собираются с одними ключами: разошедшись, сервер и агент
	// стали бы называть разные версии одной и той же сборки.
	for _, cmd := range []string{"./cmd/agent", "./cmd/netadmin"} {
		line := buildLine(helper, cmd)
		if line == "" {
			t.Errorf("в build-windows.ps1 не найдена сборка %s", cmd)
			continue
		}
		if !strings.Contains(line, "-ldflags $linkerFlags") {
			t.Errorf("сборка %s идёт без -ldflags: %s", cmd, strings.TrimSpace(line))
		}
	}
}

// buildLine — строка helper, собирающая указанный пакет.
func buildLine(yml, pkg string) string {
	for _, l := range strings.Split(yml, "\n") {
		if strings.Contains(l, "go build") && strings.Contains(l, pkg) {
			return l
		}
	}
	return ""
}
