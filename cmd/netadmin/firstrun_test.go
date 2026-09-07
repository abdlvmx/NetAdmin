package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

// withStdin подставляет ввод и перехватывает вывод меню.
//
// Возвращает функцию, которая дочитывает вывод и отдаёт его текстом. Просто
// держать буфер нельзя: пока перехват не закрыт, копирующая горутина ещё не
// дописала, и проверка содержимого получалась гонкой — первая версия этого
// теста проходила через раз.
func withStdin(t *testing.T, input string) func() string {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	go func() {
		_, _ = io.WriteString(inW, input)
		inW.Close()
	}()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	prevIn, prevOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, outR)
		close(done)
	}()

	var once sync.Once
	finish := func() string {
		once.Do(func() {
			outW.Close()
			<-done
			os.Stdin, os.Stdout = prevIn, prevOut
			inR.Close()
			outR.Close()
		})
		return buf.String()
	}
	t.Cleanup(func() { finish() })
	return finish
}

// TestFirstRunDefaultIsDemo — человек, который скачал файл и жмёт Enter, хочет
// посмотреть продукт. Демо при этом ничего не трогает в его системе, поэтому
// оно и стоит выбором по умолчанию.
func TestFirstRunDefaultIsDemo(t *testing.T) {
	for _, in := range []string{"\n", "1\n", "  \n"} {
		withStdin(t, in)
		if got := askFirstRun(); got != choiceDemo {
			t.Errorf("ввод %q дал %v, ожидалось демо", in, got)
		}
	}
}

// TestFirstRunChoices — остальные варианты меню.
func TestFirstRunChoices(t *testing.T) {
	cases := []struct {
		in   string
		want firstRunChoice
	}{
		{"2\n", choiceSetup},
		{"3\n", choiceInstall},
		{"0\n", choiceQuit},
	}
	for _, c := range cases {
		withStdin(t, c.in)
		if got := askFirstRun(); got != c.want {
			t.Errorf("ввод %q дал %v, ожидалось %v", c.in, got, c.want)
		}
	}
}

// TestFirstRunUnknownInputIsSafe — на непонятный ответ нельзя делать ничего,
// что меняет систему: показываем пример.
func TestFirstRunUnknownInputIsSafe(t *testing.T) {
	withStdin(t, "устанавливай давай\n")
	if got := askFirstRun(); got != choiceDemo {
		t.Errorf("непонятный ввод дал %v, ожидалось демо", got)
	}
}

// TestFirstRunClosedInputIsSafe — если читать не у кого (ввод закрыт), меню
// не должно зависать и не должно ничего устанавливать.
func TestFirstRunClosedInputIsSafe(t *testing.T) {
	withStdin(t, "")
	if got := askFirstRun(); got != choiceDemo {
		t.Errorf("при закрытом вводе выбрано %v, ожидалось демо", got)
	}
}

// TestFirstRunMenuMentionsOptions — меню читает человек, который не знает
// продукта: варианты должны быть названы словами, а не флагами.
func TestFirstRunMenuMentionsOptions(t *testing.T) {
	output := withStdin(t, "1")
	askFirstRun()
	out := output()
	for _, want := range []string{"Посмотреть", "Настроить", "службой"} {
		if !strings.Contains(out, want) {
			t.Errorf("в меню нет %q:\n%s", want, out)
		}
	}
}

// TestAskOnStartOnlyOnFirstRun — меню предназначено тому, кто запустил файл
// впервые. Тому, кто уже настроил продукт, оно каждый раз мешает: он открывает
// свой сервер, а его спрашивают, не хочет ли он посмотреть пример.
func TestAskOnStartOnlyOnFirstRun(t *testing.T) {
	cases := []struct {
		name                          string
		flags                         int
		ownsConsole, dataExists, want bool
	}{
		{"первый запуск двойным щелчком", 0, true, false, true},
		{"база уже есть", 0, true, true, false},
		{"запуск из терминала", 0, false, false, false},
		{"запуск с флагом", 1, true, false, false},
		{"настроен и из терминала", 0, false, true, false},
	}
	for _, c := range cases {
		if got := askOnStart(c.flags, c.ownsConsole, c.dataExists); got != c.want {
			t.Errorf("%s: получено %v, ожидалось %v", c.name, got, c.want)
		}
	}
}
