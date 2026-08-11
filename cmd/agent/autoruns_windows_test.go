//go:build windows

package main

import "testing"

// Проверяет, что сбор автозагрузки работает на реальной системе и заполняет поля.
func TestCollectAutorunsReal(t *testing.T) {
	ar := collectAutoruns()
	t.Logf("найдено точек автозагрузки: %d", len(ar))
	for _, e := range ar {
		loc, _ := e["location"].(string)
		name, _ := e["name"].(string)
		if loc == "" || name == "" {
			t.Fatalf("запись с пустым location/name: %+v", e)
		}
		if _, ok := e["command"]; !ok {
			t.Fatalf("нет поля command: %+v", e)
		}
	}
}
