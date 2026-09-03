//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"unsafe"
)

// checkInventory показывает, что агент соберёт с этой машины. Нули там, где
// ожидаются сотни, — верный признак нехватки прав: от обычного пользователя
// не читаются службы и часть реестра.
func checkInventory() int {
	fmt.Println("\nЧто соберётся с этой машины")
	hives := userHives()
	rows := []struct {
		name string
		n    int
	}{
		{"программы", len(collectSoftware())},
		{"службы", len(collectServices())},
		{"автозагрузка", len(collectAutoruns())},
		{"задачи планировщика", len(collectScheduledTasks())},
		{"диски", len(collectDisks())},
	}
	problems := 0
	for _, r := range rows {
		fmt.Printf("  %-20s %d\n", r.name, r.n)
		if r.n == 0 {
			problems++
		}
	}
	if problems > 0 {
		fmt.Println("  [ПРОБЛЕМА] часть инвентаря пуста — обычно это нехватка прав.")
		fmt.Println("             Агент должен работать задачей планировщика от SYSTEM.")
		problems = 1 // одна причина, а не по одной на каждую строку
	}

	fmt.Printf("  профили пользователей %d\n", len(hives))
	if len(hives) == 0 {
		fmt.Println("             Ни один профиль не загружен: программы и автозапуск,")
		fmt.Println("             установленные сотрудником «для себя», сейчас не видны.")
		fmt.Println("             Это нормально, если на машине никто не вошёл в систему.")
	}
	return problems
}

// holdWindow не даёт окну закрыться, когда агент запустили двойным щелчком:
// сообщение об ошибке иначе исчезает раньше, чем его успевают прочитать.
//
// Признак запуска из проводника — единственный процесс на консоли: при запуске
// из cmd или PowerShell там есть ещё и оболочка.
func holdWindow() {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	if n != 1 {
		return // запущено из консоли — она никуда не денется
	}
	fmt.Print("\nНажмите Enter, чтобы закрыть окно...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

// modkernel32 объявлен в tasks_windows.go — здесь берём из него ещё одну функцию.
var procGetConsoleProcessList = modkernel32.NewProc("GetConsoleProcessList")
