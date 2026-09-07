//go:build windows

package main

import (
	"fmt"

	"netadmin/internal/wincon"
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

// holdWindow не даёт окну закрыться, если файл запущен двойным щелчком.
// Реализация общая с сервером — см. internal/wincon.
func holdWindow() { wincon.Hold() }
