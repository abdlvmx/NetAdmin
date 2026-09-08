package agentcfg

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Настройки на общей папке лежат внутри чужого исполняемого файла, и ошибка
// здесь стоит дорого: испорченный хвост либо ломает установку у всех сразу,
// либо, что хуже, отправляет агентов не на тот сервер.

var fakeExe = []byte("MZ\x00\x00это не настоящий PE, но для хвоста разницы нет")

func TestRoundTrip(t *testing.T) {
	want := Settings{ServerURL: "http://192.168.1.10:8765", Token: "kod-registracii"}

	out, err := Append(fakeExe, want)
	if err != nil {
		t.Fatalf("дописать хвост: %v", err)
	}
	if !bytes.HasPrefix(out, fakeExe) {
		t.Fatal("исходный файл изменился — хвост должен только дописываться")
	}

	got, ok := Read(out)
	if !ok {
		t.Fatal("хвост не прочитался")
	}
	if got != want {
		t.Errorf("прочитано %+v, ожидалось %+v", got, want)
	}
}

// Повторная выдача не должна наращивать файл слоями: иначе действующими
// остались бы самые первые настройки, а файл рос бы с каждой загрузкой.
func TestAppendReplacesPreviousTrailer(t *testing.T) {
	first, _ := Append(fakeExe, Settings{ServerURL: "http://old:8765", Token: "staryj"})
	second, err := Append(first, Settings{ServerURL: "http://new:8765", Token: "novyj"})
	if err != nil {
		t.Fatalf("переписать хвост: %v", err)
	}

	got, ok := Read(second)
	if !ok {
		t.Fatal("хвост не прочитался")
	}
	if got.ServerURL != "http://new:8765" || got.Token != "novyj" {
		t.Errorf("действуют прежние настройки: %+v", got)
	}
	if len(second) != len(first)-len("staryj")+len("novyj") {
		t.Errorf("размер %d при первом %d — похоже, хвосты легли слоями",
			len(second), len(first))
	}
	if !bytes.HasPrefix(second, fakeExe) {
		t.Error("исходный файл не сохранился при переписывании хвоста")
	}
}

// Обычная сборка агента — без хвоста, и это не ошибка: настройки тогда берутся
// из файла рядом или из окружения.
func TestReadWithoutTrailer(t *testing.T) {
	for _, c := range []struct {
		name string
		data []byte
	}{
		{"обычный файл", fakeExe},
		{"пустой", nil},
		{"короче хвоста", []byte("MZ")},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := Read(c.data); ok {
				t.Error("прочитаны настройки там, где их нет")
			}
		})
	}
}

// Испорченный хвост читаться не должен: лучше «настроек нет» и понятный отказ,
// чем агент, ушедший по мусорному адресу.
func TestReadRejectsBrokenTrailer(t *testing.T) {
	good, _ := Append(fakeExe, Settings{ServerURL: "http://192.168.1.10:8765", Token: "kod"})

	t.Run("длина больше файла", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		binary.LittleEndian.PutUint32(bad[len(bad)-trailerSize:], 1<<20)
		if _, ok := Read(bad); ok {
			t.Error("принят хвост, который не помещается в файл")
		}
	})

	t.Run("нулевая длина", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		binary.LittleEndian.PutUint32(bad[len(bad)-trailerSize:], 0)
		if _, ok := Read(bad); ok {
			t.Error("принят пустой хвост")
		}
	})

	t.Run("метка есть, а внутри не JSON", func(t *testing.T) {
		body := []byte("{это не json")
		bad := append(append([]byte(nil), fakeExe...), body...)
		bad = binary.LittleEndian.AppendUint32(bad, uint32(len(body)))
		bad = append(bad, magic...)
		if _, ok := Read(bad); ok {
			t.Error("принят хвост с мусором вместо настроек")
		}
	})

	t.Run("настройки пустые", func(t *testing.T) {
		empty, _ := Append(fakeExe, Settings{})
		if _, ok := Read(empty); ok {
			t.Error("принят хвост, в котором нечего применять")
		}
	})

	t.Run("чужая метка", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		copy(bad[len(bad)-len(magic):], "NETADMIN-AGENT-CFG-9")
		if _, ok := Read(bad); ok {
			t.Error("принят хвост чужой версии формата")
		}
	})
}

// ReadFile читает с конца, не поднимая в память весь файл: у агента это десять
// мегабайт при каждом запуске.
func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	want := Settings{ServerURL: "http://192.168.1.10:8765", Token: "kod"}

	big := bytes.Repeat([]byte("x"), 3<<20)
	out, _ := Append(big, want)
	path := filepath.Join(dir, "agent.exe")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("записать файл: %v", err)
	}

	got, ok := ReadFile(path)
	if !ok {
		t.Fatal("хвост не прочитался из файла")
	}
	if got != want {
		t.Errorf("прочитано %+v, ожидалось %+v", got, want)
	}

	if err := os.WriteFile(filepath.Join(dir, "plain.exe"), big, 0o600); err != nil {
		t.Fatalf("записать файл: %v", err)
	}
	if _, ok := ReadFile(filepath.Join(dir, "plain.exe")); ok {
		t.Error("прочитаны настройки из файла без хвоста")
	}
	if _, ok := ReadFile(filepath.Join(dir, "нет-такого.exe")); ok {
		t.Error("прочитаны настройки из несуществующего файла")
	}
}
