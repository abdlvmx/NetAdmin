package handlers

import (
	"strings"
	"testing"
)

func TestLicenseUsage(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec("INSERT INTO devices (id,hostname,status) VALUES (1,'a','online'),(2,'b','online'),(3,'c','online')")
	app.DB.Exec(`INSERT INTO software (device_id,name) VALUES
		(1,'Microsoft Office 2019'),
		(1,'Microsoft Office Language Pack'),
		(2,'Microsoft Office 365'),
		(3,'LibreOffice')`)

	// две машины с Microsoft Office (device 1 учитывается один раз, несмотря на 2 записи)
	if u := app.licenseUsage("Microsoft Office"); u != 2 {
		t.Fatalf("ожидалось 2 устройства с Microsoft Office, получено %d", u)
	}
	// LibreOffice — отдельный продукт, 1 машина
	if u := app.licenseUsage("LibreOffice"); u != 1 {
		t.Fatalf("LibreOffice = 1, получено %d", u)
	}
	// несуществующее ПО
	if u := app.licenseUsage("Adobe Photoshop"); u != 0 {
		t.Fatalf("Photoshop отсутствует = 0, получено %d", u)
	}
	if u := app.licenseUsage(""); u != 0 {
		t.Fatal("пустое имя = 0")
	}
}

func TestLicenseOverage(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec("INSERT INTO devices (id,hostname,status) VALUES (1,'a','online'),(2,'b','online'),(3,'c','online')")
	app.DB.Exec(`INSERT INTO software (device_id,name) VALUES (1,'7-Zip'),(2,'7-Zip'),(3,'7-Zip')`)
	app.DB.Exec("INSERT INTO software_licenses (name, seats_purchased) VALUES ('7-Zip', 1)")

	used := app.licenseUsage("7-Zip")
	var purchased int
	app.DB.QueryRow("SELECT seats_purchased FROM software_licenses WHERE name='7-Zip'").Scan(&purchased)
	if over := used - purchased; over != 2 {
		t.Fatalf("ожидался перерасход 2 (3 исп. − 1 куплено), получено %d", over)
	}
}

// licenseUsageAll — оптимизация licenseUsage: один запрос вместо запроса на
// лицензию. Тест держит их согласованными: пока обе существуют, они обязаны
// давать одинаковый ответ на одних и тех же данных.
func TestLicenseUsageAllMatchesSingle(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec("INSERT INTO devices (id,hostname,status) VALUES (1,'a','online'),(2,'b','online'),(3,'c','online')")
	app.DB.Exec(`INSERT INTO software (device_id,name) VALUES
		(1,'Microsoft Office 2019'),
		(1,'Microsoft Office Language Pack'),
		(2,'microsoft office 2021'),
		(2,'LibreOffice'),
		(3,'7-Zip'),
		(3,'Adobe Acrobat Reader DC')`)

	names := []string{"Microsoft Office", "LibreOffice", "7-Zip", "Adobe Acrobat",
		"Photoshop", "", "  ", "microsoft office"}
	all := app.licenseUsageAll(names)
	for _, n := range names {
		want := app.licenseUsage(n)
		got := all[strings.ToLower(strings.TrimSpace(n))]
		if want != got {
			t.Errorf("%q: licenseUsage=%d, licenseUsageAll=%d", n, want, got)
		}
	}
	// Две копии Office на одной машине — это одно устройство, а не два.
	if all["microsoft office"] != 2 {
		t.Errorf("Microsoft Office: получено %d, ожидалось 2 устройства", all["microsoft office"])
	}
	if all["photoshop"] != 0 {
		t.Errorf("Photoshop нигде не установлен, получено %d", all["photoshop"])
	}
}

// Пустой список лицензий не должен приводить к запросу без условий.
func TestLicenseUsageAllEmpty(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec("INSERT INTO devices (id,hostname,status) VALUES (1,'a','online')")
	app.DB.Exec("INSERT INTO software (device_id,name) VALUES (1,'Что-то')")
	if got := app.licenseUsageAll(nil); len(got) != 0 {
		t.Fatalf("на пустом списке ожидался пустой результат: %v", got)
	}
	if got := app.licenseUsageAll([]string{"", "   "}); len(got) != 0 {
		t.Fatalf("пустые названия должны отбрасываться: %v", got)
	}
}
