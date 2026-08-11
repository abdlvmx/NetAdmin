package snmp

import (
	"testing"

	g "github.com/gosnmp/gosnmp"
)

func TestStrAndInt(t *testing.T) {
	if got := Str(g.SnmpPDU{Type: g.OctetString, Value: []byte("  switch-1 ")}); got != "switch-1" {
		t.Fatalf("Str: %q", got)
	}
	if got := Str(g.SnmpPDU{Type: g.OctetString, Value: "core-rtr"}); got != "core-rtr" {
		t.Fatalf("Str string: %q", got)
	}
	if got := Int(g.SnmpPDU{Type: g.TimeTicks, Value: uint32(360000)}); got != 360000 {
		t.Fatalf("Int timeticks: %d", got)
	}
	if got := Int(g.SnmpPDU{Type: g.Integer, Value: 87}); got != 87 {
		t.Fatalf("Int integer: %d", got)
	}
	if got := Int(g.SnmpPDU{Type: g.Null, Value: nil}); got != 0 {
		t.Fatalf("Int nil: %d", got)
	}
}

func TestUsable(t *testing.T) {
	if Usable(g.SnmpPDU{Type: g.NoSuchObject}) {
		t.Fatal("NoSuchObject должен быть непригоден")
	}
	if !Usable(g.SnmpPDU{Type: g.Integer, Value: 1}) {
		t.Fatal("Integer должен быть пригоден")
	}
}

func TestSummarizePorts(t *testing.T) {
	up, down, total := SummarizePorts([]int64{1, 1, 2, 6, 1, 7})
	if up != 3 || down != 2 || total != 5 {
		t.Fatalf("ports up=%d down=%d total=%d (ожидалось 3/2/5)", up, down, total)
	}
}

func TestBatteryAndSource(t *testing.T) {
	if BatteryStatusText(3) != "низкий заряд" {
		t.Fatalf("battery 3: %q", BatteryStatusText(3))
	}
	if !OnBattery(5) || OnBattery(3) {
		t.Fatal("OnBattery: 5=да, 3=нет")
	}
}

func TestSupplyPct(t *testing.T) {
	if p, ok := SupplyPct(50, 200); !ok || p != 25 {
		t.Fatalf("supply 50/200: %d ok=%v (ожидалось 25)", p, ok)
	}
	if _, ok := SupplyPct(-2, 200); ok {
		t.Fatal("уровень -2 (unknown) → известность=false")
	}
	if _, ok := SupplyPct(10, 0); ok {
		t.Fatal("max=0 → известность=false")
	}
}
