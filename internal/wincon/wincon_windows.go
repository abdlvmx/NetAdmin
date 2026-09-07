//go:build windows

package wincon

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	shell32          = windows.NewLazySystemDLL("shell32.dll")
	procShellExecute = shell32.NewProc("ShellExecuteW")

	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
)

// OwnsConsole сообщает, что окно консоли принадлежит только этому процессу, —
// признак запуска двойным щелчком. Тогда окно закроется вместе с процессом,
// и всё напечатанное пропадёт, не успев быть прочитанным.
func OwnsConsole() bool {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

// Hold не даёт окну закрыться, если запущено двойным щелчком.
func Hold() {
	if !OwnsConsole() {
		return
	}
	fmt.Print("\nНажмите Enter, чтобы закрыть окно...")
	readLine()
}

// AskLine спрашивает строку. Второе значение — false, если спрашивать не у кого
// (ввод закрыт): вызывающий не должен принимать это за пустой ответ и идти
// дальше, как будто человек нажал Enter.
func AskLine(prompt string) (string, bool) {
	fmt.Print(prompt)
	line, ok := readLine()
	if !ok {
		fmt.Println()
		return "", false
	}
	return strings.TrimSpace(line), true
}

// AskYesNo задаёт вопрос с ответом по умолчанию «да».
func AskYesNo(question string) bool {
	ans, ok := AskLine(question + " [Y/n] ")
	if !ok {
		return false
	}
	a := strings.ToLower(ans)
	return a == "" || a == "y" || a == "yes" || a == "д" || a == "да"
}

// Elevate перезапускает текущий процесс с запросом прав администратора и
// сообщает, что запуск состоялся: вызывающий должен завершиться.
//
// Так же поступают обычные установщики: человеку, скачавшему один файл, незачем
// знать про «запустить консоль от имени администратора» — Windows умеет
// спросить сама. Манифест в ресурсах потребовал бы внешнего инструмента сборки,
// а этот путь обходится средствами системы.
func Elevate(args ...string) (bool, error) {
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(joinArgs(args))
	dir, _ := windows.UTF16PtrFromString("")

	const swShowNormal = 1
	r, _, err := procShellExecute.Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)), uintptr(unsafe.Pointer(dir)),
		swShowNormal)

	// ShellExecuteW возвращает значение больше 32 при успехе. Отказ в UAC —
	// ERROR_CANCELLED (1223), и это не ошибка программы: человек передумал.
	if r <= 32 {
		if r == 1223 {
			return false, fmt.Errorf("запрос прав администратора отклонён")
		}
		return false, fmt.Errorf("не удалось запросить права администратора (код %d): %v", r, err)
	}
	return true, nil
}

// joinArgs собирает командную строку, беря в кавычки аргументы с пробелами:
// без этого адрес каталога с пробелом разъехался бы на два аргумента.
func joinArgs(args []string) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		if strings.ContainsAny(a, " \t") {
			a = `"` + a + `"`
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}
