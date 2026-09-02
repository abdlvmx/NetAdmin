package handlers

import "testing"

func TestCSVSafeBlocksFormulaInjection(t *testing.T) {
	// Значения, которые табличный процессор принял бы за формулу.
	for _, in := range []string{
		"=cmd|'/c calc'!A1",
		"+1+1",
		"-2+3+cmd",
		"@SUM(A1:A9)",
		"\tformula",
		"\rformula",
	} {
		got := csvSafe(in)
		if got != "'"+in {
			t.Errorf("csvSafe(%q) = %q, ожидался ведущий апостроф", in, got)
		}
	}
}

func TestCSVSafeLeavesNormalValues(t *testing.T) {
	// Обычные значения инвентаря не должны меняться.
	for _, in := range []string{
		"PC-0142", "192.168.1.10", "Смирнова Ольга", "каб. 201",
		"Windows 10 Pro", "", "Intel Core i5-10400",
	} {
		if got := csvSafe(in); got != in {
			t.Errorf("csvSafe(%q) = %q, значение изменено без причины", in, got)
		}
	}
}
