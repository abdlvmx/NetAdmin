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
// администраторов (S-1-5-32-544), наследование от %ProgramData% отключено,
// а владельцем становится тот, кому каталог и должен принадлежать.
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
	owner, name, err := ownerOf(dir)
	if err != nil {
		t.Fatalf("владелец: %v", err)
	}
	if !trustedOwner(owner) {
		t.Errorf("владельцем заведённого нами каталога стал %s — такой каталог "+
			"следующая установка отвергла бы как чужой", name)
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

// Чужой владелец не доверяется, как бы ни выглядели права.
//
// Это главная проверка пакета. Список доступа подделывается: тот, кто занял
// каталог до установщика, сам выставит на него ровно те записи, которые мы
// ищем. При этом он остаётся владельцем, а владельцу Windows всегда неявно
// даёт WRITE_DAC — вернуть себе полный доступ и подменить файл службы,
// работающей от SYSTEM, он сможет в любой момент после установки.
func TestForeignOwnerIsNotTrusted(t *testing.T) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, sid := range []*windows.SID{system, admins} {
		if !trustedOwner(sid) {
			t.Errorf("%s должен считаться своим владельцем", sid)
		}
	}

	// Обычный пользователь и встроенная группа «Пользователи» — не свои.
	for _, s := range []string{"S-1-5-21-1111111111-2222222222-3333333333-1001", "S-1-5-32-545"} {
		sid, err := windows.StringToSid(s)
		if err != nil {
			t.Fatal(err)
		}
		if trustedOwner(sid) {
			t.Errorf("%s принят как свой владелец — каталог, занятый до установщика, "+
				"прошёл бы проверку", s)
		}
	}
}

// Каталог с правильными правами, но чужим владельцем — отказ. Тот самый обход
// целиком: права выставлены ровно те, что ставим мы сами, и только владелец
// выдаёт подделку.
func TestSecureRefusesForeignOwnerDespiteCorrectACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "NetAdmin")
	openUp(t, dir)
	if _, err := Secure(dir); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	// Владелец меняется на встроенную группу «Пользователи»: она есть в токене
	// администратора, поэтому особых привилегий смена не требует, — а доверенной
	// она не считается.
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, users, nil, nil, nil); err != nil {
		t.Skipf("сменить владельца в этом окружении не удалось: %v", err)
	}

	_, err = Secure(dir)
	if err == nil {
		t.Fatal("каталог с чужим владельцем принят, хотя права на нём выглядят правильно")
	}
	if !strings.Contains(err.Error(), "удалите или переименуйте") {
		t.Errorf("в отказе нет продолжения о том, что делать: %v", err)
	}
}

// Обновление поверх установки прежних версий, где права не выставлялись.
// Отказать здесь значило бы сломать обновление всем, кто уже поставил продукт:
// каталог свой, просто открытый.
func TestSecureTightensPreviousInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "NetAdmin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	openUp(t, dir)

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
