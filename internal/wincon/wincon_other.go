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
