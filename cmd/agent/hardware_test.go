package main

import "testing"

func TestHardwareInfoReal(t *testing.T) {
	hw := hardwareInfo()
	t.Logf("железо: %+v", hw)
	if ram, _ := hw["ram_total_gb"].(int); ram <= 0 {
		t.Fatalf("ram_total_gb должен быть > 0, получено %v", hw["ram_total_gb"])
	}
	if osv, _ := hw["os_version"].(string); osv == "" {
		t.Fatal("os_version пуст")
	}
}
