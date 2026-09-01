//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/exec"
	"strings"
)

// restartPending — подмена прошла, осталось перезапуститься. Флаг проверяется
// после отправки результата задачи: сначала сервер узнаёт исход, потом процесс
// уступает место новой сборке.
var restartPending bool

// cleanupOldBinary убирает следы прошлого обновления. Вызывается при старте:
// к этому моменту новая сборка уже отработала запуск, откат больше не нужен.
func cleanupOldBinary() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	_ = os.Remove(exe + ".old")
	_ = os.Remove(exe + ".new")
}

// selfUpdate скачивает новую сборку агента, проверяет её и подменяет себя.
//
// Порядок шагов важен. Файл сначала сверяется по контрольной сумме из
// подписанной задачи, затем запускается с -version как проверка, что он вообще
// рабочий, и только после этого занимает место текущего. Прежняя сборка
// сохраняется рядом: если подмена сорвётся на полпути, она вернётся на место.
// Без проверки запуском битый файл превратил бы обновление парка в его отказ.
func selfUpdate(payload string) (status, output string, code int) {
	var p struct {
		ID     int64  `json:"id"`
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	}
	if json.Unmarshal([]byte(payload), &p) != nil || p.ID == 0 {
		return "failed", "некорректные данные обновления", 1
	}
	if p.SHA256 == "" {
		return "failed", "сборка без контрольной суммы — обновление отклонено", 1
	}

	exe, err := os.Executable()
	if err != nil {
		return "failed", "не удалось определить путь к агенту: " + err.Error(), 1
	}
	newPath, oldPath := exe+".new", exe+".old"

	_ = os.Remove(newPath)
	if err := downloadPackage(p.ID, newPath); err != nil {
		return "failed", "скачивание: " + err.Error(), 1
	}
	sum, err := fileSHA256(newPath)
	if err != nil {
		_ = os.Remove(newPath)
		return "failed", "проверка контрольной суммы: " + err.Error(), 1
	}
	if !strings.EqualFold(sum, p.SHA256) {
		_ = os.Remove(newPath)
		return "failed", "контрольная сумма не совпала — сборка подменена или повреждена", 1
	}

	ver, err := probeBinary(newPath)
	if err != nil {
		_ = os.Remove(newPath)
		return "failed", "новая сборка не запускается: " + err.Error(), 1
	}
	if ver == agentVersion {
		_ = os.Remove(newPath)
		return "done", "уже установлена версия " + ver + ", обновление не требуется", 0
	}

	_ = os.Remove(oldPath)
	// работающий .exe нельзя перезаписать, но можно переименовать
	if err := os.Rename(exe, oldPath); err != nil {
		_ = os.Remove(newPath)
		return "failed", "не удалось освободить файл агента: " + err.Error(), 1
	}
	if err := os.Rename(newPath, exe); err != nil {
		_ = os.Rename(oldPath, exe) // возвращаем прежнюю сборку на место
		_ = os.Remove(newPath)
		return "failed", "не удалось поставить новую сборку: " + err.Error(), 1
	}

	restartPending = true
	return "done", "обновление " + agentVersion + " → " + ver + ", перезапуск", 0
}

// probeBinary проверяет, что скачанный файл — рабочий агент: он обязан
// ответить на -version непустой строкой.
func probeBinary(path string) (string, error) {
	cmd := exec.Command(path, "-version")
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "", errors.New("пустой ответ на -version")
	}
	return v, nil
}

// restartIntoNewBinary запускает подменённый бинарник и уступает ему место.
//
// Задача планировщика стартует агента только при загрузке ПК, поэтому просто
// завершиться нельзя — машина осталась бы без агента до перезагрузки.
func restartIntoNewBinary() {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("перезапуск: %v", err)
		return
	}
	cmd := exec.Command(exe)
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		log.Printf("перезапуск не удался: %v — агент продолжит работу до перезагрузки", err)
		return
	}
	log.Print("новая сборка запущена, завершаюсь")
	os.Exit(0)
}
