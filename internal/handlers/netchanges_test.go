package handlers

import "testing"

func TestRecordNetChange(t *testing.T) {
	app := newTestApp(t)

	app.recordNetChange("new", "192.168.1.50", "AA:BB:CC:DD:EE:01", "ws-50", "Dell", "")
	app.recordNetChange("new", "192.168.1.51", "AA:BB:CC:DD:EE:02", "ws-51", "HP", "")
	app.recordNetChange("gone", "192.168.1.10", "AA:BB:CC:DD:EE:03", "ws-10", "", "")
	app.recordNetChange("changed", "192.168.1.20", "AA:BB:CC:DD:EE:04", "ws-20", "Asus", "MAC: old → new")

	cnt := func(t string) int {
		return countRows(app, "SELECT COUNT(*) FROM network_changes WHERE change_type='"+t+"'")
	}
	if cnt("new") != 2 {
		t.Fatalf("ожидалось 2 'new', получено %d", cnt("new"))
	}
	if cnt("gone") != 1 {
		t.Fatalf("ожидалось 1 'gone', получено %d", cnt("gone"))
	}
	if cnt("changed") != 1 {
		t.Fatalf("ожидалось 1 'changed', получено %d", cnt("changed"))
	}

	// деталь изменения сохраняется
	var detail string
	app.DB.QueryRow("SELECT detail FROM network_changes WHERE change_type='changed'").Scan(&detail)
	if detail == "" {
		t.Fatal("деталь изменения не сохранилась")
	}
	// всего записей
	if all := countRows(app, "SELECT COUNT(*) FROM network_changes"); all != 4 {
		t.Fatalf("ожидалось 4 записи всего, получено %d", all)
	}
}
