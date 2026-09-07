package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sumOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Сборка агента не должна попадать в общий каталог временных файлов.
//
// Прежде она писалась в os.TempDir() под постоянным именем. У службы это
// C:\Windows\Temp, куда может писать любой пользователь: занятый заранее файл
// остаётся во владении того, кто его создал, а запускается он от LocalSystem.
func TestStageAgentKeepsTheBuildInsideTheGivenDirectory(t *testing.T) {
	dir := t.TempDir()
	data := []byte("это сборка агента")

	exe, cleanup, err := stageAgent(dir, data, sumOf(data))
	if err != nil {
		t.Fatalf("stageAgent: %v", err)
	}
	defer cleanup()

	if !strings.HasPrefix(exe, dir+string(os.PathSeparator)) {
		t.Errorf("файл агента лёг вне выданного каталога: %s (ожидался внутри %s)", exe, dir)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatalf("чтение записанного файла: %v", err)
	}
	if string(got) != string(data) {
		t.Error("записано не то, что просили записать")
	}
}

// Имя не должно повторяться: постоянное имя и было тем, что позволяло занять
// файл заранее.
func TestStageAgentUsesAFreshNameEachTime(t *testing.T) {
	dir := t.TempDir()
	data := []byte("сборка")

	first, cleanup1, err := stageAgent(dir, data, sumOf(data))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup1()
	second, cleanup2, err := stageAgent(dir, data, sumOf(data))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup2()

	if first == second {
		t.Errorf("оба раза выбран один путь %s — занять его заранее снова возможно", first)
	}
}

// Файл, не совпавший с контрольной суммой, не должен дойти до запуска.
//
// Сумма встроенной сборки считается в agentbin и прежде просто отбрасывалась.
// Между записью и запуском файл меняет не только злоумышленник — антивирус
// вправе вырезать или подменить его.
func TestStageAgentRefusesBuildThatDoesNotMatchItsSum(t *testing.T) {
	dir := t.TempDir()

	_, cleanup, err := stageAgent(dir, []byte("сборка"), sumOf([]byte("совсем другое")))
	if err == nil {
		cleanup()
		t.Fatal("сборка с неверной суммой принята")
	}
	if !strings.Contains(err.Error(), "контрольной суммой") {
		t.Errorf("отказ не называет причину: %v", err)
	}

	// За собой убрано: файл, не прошедший проверку, оставлять на диске незачем.
	left, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		names := make([]string, 0, len(left))
		for _, e := range left {
			names = append(names, filepath.Join(dir, e.Name()))
		}
		t.Errorf("после отказа остались файлы: %v", names)
	}
}
