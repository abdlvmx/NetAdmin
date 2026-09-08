//go:build !windows

package wincon

import (
	"fmt"
	"strings"
)

// Вне Windows окно консоли никто не закрывает за процессом, поэтому Hold
// ничего не ждёт, а UAC не существует.

func OwnsConsole() bool { return false }
func Hold()             {}

func AskLine(prompt string) (string, bool) {
	fmt.Print(prompt)
	line, ok := readLine()
	if !ok {
		fmt.Println()
		return "", false
	}
	return strings.TrimSpace(line), true
}

// AskSecret вне Windows не умеет спрятать набранное: гасить отражение ввода
// нечем — терминалом заведует пакет, которого в зависимостях нет и заводить
// его ради одной команды не стоит. Поэтому вместо тихой видимости честно
// предупреждаем: пароль останется в окне.
func AskSecret(prompt string) (string, bool) {
	fmt.Println("  (ввод виден на экране: скрыть его на этой системе нечем)")
	fmt.Print(prompt)
	line, ok := readLine()
	return line, ok
}

func AskYesNo(question string) bool {
	ans, ok := AskLine(question + " [Y/n] ")
	if !ok {
		return false
	}
	a := strings.ToLower(ans)
	return a == "" || a == "y" || a == "yes" || a == "д" || a == "да"
}

func Elevate(...string) (bool, error) {
	return false, fmt.Errorf("повышение прав доступно только в Windows")
}
