//go:build windows

package instdir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// openUp возвращает каталогу открытый доступ, чтобы уборка после теста прошла.
//
// Закрытый каталог создатель удалить уже не может: своих прав в списке не
// осталось. Владельцу, однако, WRITE_DAC принадлежит всегда — этим и
// пользуемся. Пустой (NULL) список означает «доступ всем» и снимает вопрос и с
// вложенными файлами: удаление ребёнка разрешает родитель.
func openUp(t *testing.T, dir string) {
	t.Helper()
	t.Cleanup(func() {
		_ = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, nil, nil)
	})
}

// aceSIDs — кому список доступа каталога что-то разрешает.
func aceSIDs(t *testing.T, dir string) []string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("чтение прав %s: %v", dir, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("список доступа: %v", err)
	}
	if dacl == nil {
		t.Fatal("список доступа пуст (NULL DACL) — это открытый всем каталог")
	}
	var out []string
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("запись %d: %v", i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		out = append(out, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	return out
}

// Каталог заводится закрытым: доступ только у SYSTEM (S-1-5-18) и встроенных
// администраторов (S-1-5-32-544), наследование от C:\ProgramData отключено.
// Именно наследование и было дырой: там BUILTIN\Users может создавать файлы,
// а CREATOR OWNER отдаёт созданное создателю.
func TestSecureCreatesDirectoryClosedToUsers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "NetAdmin")
	openUp(t, dir)

	tightened, err := Secure(dir)
	if err != nil {
		t.Fatalf("Secure: %v", err)
	}
	if tightened {
		t.Error("новый каталог не должен считаться исправленным: чинить было нечего")
	}

	got := aceSIDs(t, dir)
	want := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	for _, sid := range got {
		if !want[sid] {
			t.Errorf("каталогу установки разрешён доступ для %s — здесь лежат токены агентов "+
				"и хеши паролей, доступ должен быть только у SYSTEM и администраторов", sid)
		}
	}
	if len(got) != len(want) {
		t.Errorf("разрешающих записей %d (%v), ожидалось %d", len(got), got, len(want))
	}

	if closed, err := restricted(dir); err != nil || !closed {
		t.Errorf("restricted(%s) = %v, %v; каталог должен опознаваться как закрытый", dir, closed, err)
	}
}

// Повторная установка поверх своего же каталога не должна сообщать, что чинила
// права: чинить нечего, и лишняя строка в выводе установщика — ложная тревога.
func TestSecureOnClosedDirectoryChangesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "NetAdmin")
	openUp(t, dir)
	if _, err := Secure(dir); err != nil {
		t.Fatalf("первая установка: %v", err)
	}

	tightened, err := Secure(dir)
	if err != nil {
		t.Fatalf("повторная установка: %v", err)
	}
	if tightened {
		t.Error("права уже выставлены — исправлять было нечего")
	}
}

// Каталог, занятый до установщика: существует, открыт на запись и пуст. Это и
// есть атака — тот, кто занял место, остаётся владельцем и подменяет файл
// службы, работающей от SYSTEM. Установка должна отказаться, а не «починить»
// чужое место и поселиться в нём.
func TestSecureRefusesDirectoryTakenBeforeInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "NetAdmin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := Secure(dir)
	if err == nil {
		t.Fatal("установка в чужой открытый каталог должна отклоняться")
	}
	// Отказ обязан говорить, что делать: иначе человек упрётся в него и решит,
	// что установщик сломан.
	if !strings.Contains(err.Error(), "удалите или переименуйте") {
		t.Errorf("в отказе нет продолжения о том, что делать: %v", err)
	}
}

// Обновление поверх установки прежних версий, где права не выставлялись. Такой
// каталог отличается от занятого чужаком тем, что в нём лежит наше: отказать
// здесь значило бы сломать обновление всем, кто уже поставил продукт.
func TestSecureTightensPreviousInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "NetAdmin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	openUp(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "netadmin.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	tightened, err := Secure(dir)
	if err != nil {
		t.Fatalf("Secure: %v", err)
	}
	if !tightened {
		t.Error("права у прежней установки были открытыми — установщик должен сообщить, что закрыл их")
	}
	if closed, err := restricted(dir); err != nil || !closed {
		t.Errorf("restricted(%s) = %v, %v; после починки каталог должен быть закрыт", dir, closed, err)
	}
}
