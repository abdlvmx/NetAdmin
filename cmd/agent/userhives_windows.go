//go:build windows

package main

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// userHive — куст реестра пользователя, загруженный в HKEY_USERS.
type userHive struct {
	SID     string // S-1-5-21-…
	Name    string // имя папки профиля: Ivanov
	Profile string // путь к профилю: C:\Users\Ivanov
}

// userHives перечисляет кусты реальных пользователей из HKEY_USERS.
//
// Агент работает от SYSTEM, и HKEY_CURRENT_USER для него — профиль самой
// учётной записи SYSTEM, а не сотрудника за машиной. Пока сбор шёл только по
// HKLM и такому «своему» HKCU, из инвентаря выпадало всё, что человек поставил
// для себя: Discord, Telegram, игровые лаунчеры и их автозапуск. Для аудита
// запрещённого ПО это была дыра — торрент-клиент, поставленный per-user,
// система не видела.
//
// Куст виден здесь, только пока пользователь в системе (или его профиль
// загружен по другой причине). Для машин, где никто не вошёл, пользовательская
// часть соберётся при следующем сборе — это ограничение самой Windows, а не
// агента.
func userHives() []userHive {
	k, err := registry.OpenKey(registry.USERS, "", registry.READ)
	if err != nil {
		return nil
	}
	defer k.Close()
	sids, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	var out []userHive
	for _, sid := range sids {
		if !isUserSID(sid) {
			continue
		}
		h := userHive{SID: sid}
		// путь к профилю берём из ProfileList — по нему же узнаём имя
		if pk, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid,
			registry.READ); err == nil {
			h.Profile, _, _ = pk.GetStringValue("ProfileImagePath")
			pk.Close()
		}
		if h.Profile != "" {
			h.Name = filepath.Base(h.Profile)
		} else {
			h.Name = sid
		}
		out = append(out, h)
	}
	return out
}

// isUserSID отсеивает всё, что не является учётной записью человека.
//
// S-1-5-21-… — обычные локальные и доменные пользователи. Мимо идут системные
// учётные записи (S-1-5-18 SYSTEM, 19 LOCAL SERVICE, 20 NETWORK SERVICE),
// шаблон .DEFAULT и вспомогательные кусты _Classes, которые дублируют
// содержимое основного и только удвоили бы инвентарь.
func isUserSID(sid string) bool {
	return strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasSuffix(sid, "_Classes")
}
