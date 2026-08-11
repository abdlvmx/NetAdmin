package handlers

import "testing"

func TestForbiddenScan(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec("INSERT INTO devices (id,hostname,status) VALUES (1,'class-1','online'),(2,'class-2','online'),(3,'lab-1','online')")
	app.DB.Exec(`INSERT INTO software (device_id,name) VALUES
		(1,'uTorrent 3.5'),
		(1,'Microsoft Office'),
		(2,'Steam'),
		(2,'qBittorrent'),
		(3,'7-Zip')`)
	app.DB.Exec(`INSERT INTO forbidden_software (pattern,category) VALUES
		('utorrent','Торренты'),('qbittorrent','Торренты'),('steam','Игры'),('xmrig','Майнеры')`)

	rules, findings, hosts := app.forbiddenScan()
	if len(rules) != 4 {
		t.Fatalf("ожидалось 4 правила, получено %d", len(rules))
	}
	// находки: uTorrent(class-1), qBittorrent(class-2), Steam(class-2) = 3; xmrig нет
	if len(findings) != 3 {
		t.Fatalf("ожидалось 3 находки, получено %d (%v)", len(findings), findings)
	}
	// затронуто 2 ПК (class-1, class-2)
	if hosts != 2 {
		t.Fatalf("ожидалось 2 затронутых ПК, получено %d", hosts)
	}
	// чистый ПК lab-1 не должен попасть
	for _, f := range findings {
		if f.Hostname == "lab-1" {
			t.Fatal("чистый ПК не должен быть в находках")
		}
	}
}
