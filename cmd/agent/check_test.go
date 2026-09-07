package main

import "testing"

// Агент от SYSTEM видит реестр и службы целиком; от обычной учётной записи
// часть инвентаря недоступна, и проверка должна об этом сказать.
func TestIsSystemAccount(t *testing.T) {
	for _, name := range []string{
		`NT AUTHORITY\SYSTEM`,
		`nt authority\system`,
		`СИСТЕМА\SYSTEM`,
	} {
		if !isSystemAccount(name) {
			t.Errorf("%q — системная учётная запись", name)
		}
	}
	for _, name := range []string{
		`DESKTOP-LTKG4LO\abdlvmx`,
		`FIRMA\ivanov`,
		"",
	} {
		if isSystemAccount(name) {
			t.Errorf("%q — обычный пользователь, не SYSTEM", name)
		}
	}
}
