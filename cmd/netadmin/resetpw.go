package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/config"
	"netadmin/internal/db"
	"netadmin/internal/wincon"
)

// Восстановление доступа: `netadmin.exe -reset-password`.
//
// Единственный администратор, забывший пароль, до сих пор оставался с
// работающим сервером, в который нельзя войти. Пароли хранятся хешами, сбросить
// их через интерфейс некому — админ там ровно один, — и восстановления не было
// нигде: ни флага, ни строчки в документации. Для продукта, который скачивают
// одним файлом и ставят себе сами, это вопрос времени, а не «если».
//
// Права запрашиваются через UAC: база лежит в каталоге, куда пускают только
// SYSTEM и администраторы машины (instdir.Secure). Это же и есть граница
// доверия — кто может здесь сбросить пароль, тот может и подменить сам файл
// службы; отдельной защиты команда не снимает и не добавляет.

// resetPasswordArgs — как передать задачу копии, запущенной с правами.
func resetPasswordArgs(user string) []string {
	args := []string{"-reset-password"}
	if user != "" {
		args = append(args, "-user="+user)
	}
	return args
}

// installedDBPath — база установленной службы. Вынесена в переменную ради
// тестов: иначе проверка «базы нет» на машине с установленной службой нашла бы
// настоящую базу и поменяла пароль в ней.
var installedDBPath = func() string { return filepath.Join(installDir(), "netadmin.db") }

// account — учётная запись, которой меняем пароль.
type account struct {
	id       int64
	username string
	fullName string
	role     string
	active   bool
}

// title — как назвать запись человеку.
func (a account) title() string {
	s := a.username
	if a.fullName != "" {
		s += " (" + a.fullName + ")"
	}
	if !a.active {
		s += " — отключена"
	}
	return s
}

// resetPassword задаёт новый пароль администратору.
func resetPassword(login string) error {
	path, err := resetDBPath()
	if err != nil {
		return err
	}
	d, err := db.Open(path)
	if err != nil {
		return fmt.Errorf("открыть базу %s: %w", path, err)
	}
	defer d.Close()

	fmt.Println()
	fmt.Println("Смена пароля администратора")
	fmt.Println("  База:", path)

	acc, err := pickAccount(d, login)
	if err != nil {
		return err
	}

	pw, err := askNewPassword(acc)
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return fmt.Errorf("вычислить хеш пароля: %w", err)
	}
	if _, err := d.Exec("UPDATE users SET password_hash=? WHERE id=?", hash, acc.id); err != nil {
		return fmt.Errorf("записать пароль: %w", err)
	}

	// Прежние сессии гасим все до одной. Пароль меняют, когда доступ потерян
	// или скомпрометирован; оставить работающей чужую вкладку значило бы
	// сменить замок, не отобрав старый ключ.
	if _, err := d.Exec("DELETE FROM sessions WHERE user_id=?", acc.id); err != nil {
		fmt.Println("  Предупреждение: прежние сессии не удалось закрыть:", err)
	}

	enabled := ""
	if !acc.active {
		if wincon.AskYesNo("\n  Учётная запись отключена, с ней не войти. Включить?") {
			if _, err := d.Exec("UPDATE users SET is_active=1 WHERE id=?", acc.id); err != nil {
				return fmt.Errorf("включить учётную запись: %w", err)
			}
			enabled = ", учётная запись включена"
		} else {
			fmt.Println("  Оставлена отключённой — войти под ней по-прежнему нельзя.")
		}
	}

	// В журнале это действие остаётся без автора: его совершил не вошедший
	// пользователь, а тот, у кого есть права администратора на самой машине.
	// Журнал показывает такие записи как «система», и это честнее, чем
	// приписать их владельцу учётной записи.
	auth.LogAction(d, 0, "password_reset_console", acc.username,
		"пароль задан с консоли сервера"+enabled)

	fmt.Println()
	fmt.Printf("Готово: пароль для «%s» изменён%s.\n", acc.username, enabled)
	fmt.Println("Прежние сессии закрыты — войдите заново на http://127.0.0.1:8765")
	return nil
}

// resetDBPath — база, у которой меняем пароль.
//
// Каталог данных — это каталог запущенного файла, и у установленной службы это
// C:\ProgramData\NetAdmin. Но запустить команду человек может и той копией,
// которую скачал: рядом с ней базы нет, а менять пароль надо в той, с которой
// работает служба. Поэтому смотрим оба места — и печатаем выбранное, чтобы не
// пришлось гадать, где именно пароль поменялся.
func resetDBPath() (string, error) {
	paths := []string{config.DBPath()}
	if inst := installedDBPath(); inst != paths[0] {
		paths = append(paths, inst)
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("база не найдена (искали в %s).\n"+
		"Похоже, сервер ещё не настроен: первый администратор заводится в мастере\n"+
		"первого запуска, который открывается сам при первом старте",
		strings.Join(paths, " и в "))
}

// pickAccount выбирает, кому менять пароль.
//
// Без -user рассматриваются только администраторы: команда существует ради
// потерянного доступа ко всей панели, а не как обход страницы «Пользователи».
// С явным -user меняем пароль любому — чтобы администратор, у которого своя
// учётная запись цела, мог помочь коллеге, не заводя ему новую.
func pickAccount(d *sql.DB, login string) (account, error) {
	if login != "" {
		acc, err := accountByName(d, login)
		if err != nil {
			return account{}, err
		}
		fmt.Println("  Учётная запись:", acc.title())
		return acc, nil
	}

	admins, err := listAdmins(d)
	if err != nil {
		return account{}, err
	}
	switch len(admins) {
	case 0:
		return account{}, fmt.Errorf("в базе нет ни одного администратора.\n" +
			"Задайте -user=<логин>, если знаете нужную учётную запись")
	case 1:
		fmt.Println("  Учётная запись:", admins[0].title())
		return admins[0], nil
	}

	fmt.Println()
	fmt.Println("  Администраторов несколько — кому меняем пароль?")
	for i, a := range admins {
		fmt.Printf("  %d  %s\n", i+1, a.title())
	}
	fmt.Println("  0  Отмена")
	ans, ok := wincon.AskLine("\n  Ваш выбор: ")
	if !ok {
		return account{}, fmt.Errorf("ввод закрыт — ничего не изменено")
	}
	n, err := strconv.Atoi(strings.TrimSpace(ans))
	if err != nil || n < 0 || n > len(admins) {
		return account{}, fmt.Errorf("непонятный выбор %q — ничего не изменено", ans)
	}
	if n == 0 {
		return account{}, fmt.Errorf("отменено — ничего не изменено")
	}
	return admins[n-1], nil
}

func accountByName(d *sql.DB, login string) (account, error) {
	var a account
	err := d.QueryRow(`SELECT id, username, COALESCE(full_name,''), COALESCE(role,''), is_active
		FROM users WHERE username=?`, login).
		Scan(&a.id, &a.username, &a.fullName, &a.role, &a.active)
	if err == sql.ErrNoRows {
		names, _ := listAdmins(d)
		if len(names) == 0 {
			return account{}, fmt.Errorf("учётной записи %q в базе нет", login)
		}
		var titles []string
		for _, n := range names {
			titles = append(titles, n.username)
		}
		return account{}, fmt.Errorf("учётной записи %q в базе нет.\nАдминистраторы: %s",
			login, strings.Join(titles, ", "))
	}
	if err != nil {
		return account{}, fmt.Errorf("поиск учётной записи: %w", err)
	}
	return a, nil
}

func listAdmins(d *sql.DB) ([]account, error) {
	rows, err := d.Query(`SELECT id, username, COALESCE(full_name,''), COALESCE(role,''), is_active
		FROM users WHERE role='admin' ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("список администраторов: %w", err)
	}
	defer rows.Close()
	var out []account
	for rows.Next() {
		var a account
		if err := rows.Scan(&a.id, &a.username, &a.fullName, &a.role, &a.active); err != nil {
			return nil, fmt.Errorf("список администраторов: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// askNewPassword спрашивает пароль дважды и проверяет политику.
func askNewPassword(acc account) (string, error) {
	fmt.Println()
	fmt.Printf("  Новый пароль для «%s».\n", acc.username)
	fmt.Println("  Требования те же, что в интерфейсе: не меньше 8 символов,")
	fmt.Println("  хотя бы одна буква и одна цифра. Набранное не отображается.")
	fmt.Println()

	pw, ok := wincon.AskSecret("  Пароль:  ")
	if !ok {
		return "", fmt.Errorf("ввод закрыт — пароль не изменён")
	}
	if auth.WeakPassword(pw) {
		return "", fmt.Errorf("пароль не отвечает требованиям " +
			"(не меньше 8 символов, буква и цифра) — пароль не изменён")
	}
	again, ok := wincon.AskSecret("  Ещё раз: ")
	if !ok {
		return "", fmt.Errorf("ввод закрыт — пароль не изменён")
	}
	if pw != again {
		return "", fmt.Errorf("пароли не совпали — пароль не изменён")
	}
	return pw, nil
}
