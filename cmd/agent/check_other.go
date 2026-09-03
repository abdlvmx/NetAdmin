//go:build !windows

package main

import "fmt"

// checkInventory — на не-Windows агент шлёт только метрики, инвентарь
// конфигурации не собирается.
func checkInventory() int {
	fmt.Println("\nЧто соберётся с этой машины")
	fmt.Println("  инвентарь ПО, служб и автозагрузки собирается только на Windows")
	return 0
}

// holdWindow нужен только там, где агент запускают двойным щелчком.
func holdWindow() {}
