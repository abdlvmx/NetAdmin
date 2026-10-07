package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

// withStdin подставляет ввод и перехватывает вывод диалога. Возвращает
// функцию, которая дочитывает вывод: пока перехват не закрыт, копирующая
// горутина ещё пишет, и проверять содержимое буфера было бы гонкой.
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

// TestAskSetupCollectsAndNormalizes — то, ради чего диалог и заведён: человек
// вводит адрес как ему привычно, а агенту он нужен полным.
func TestAskSetupCollectsAndNormalizes(t *testing.T) {
	withStdin(t, "192.168.1.10:8765\nКОД-123\n\n")

	server, code, ok := askSetup("", "")
	if !ok {
		t.Fatal("диалог не завершился успехом")
	}
	if server != "http://192.168.1.10:8765" {
		t.Errorf("адрес %q, ожидался достроенный до полного вида", server)
	}
	if code != "КОД-123" {
		t.Errorf("код %q", code)
	}
}

// TestAskSetupAddsDefaultPort — вводят чаще всего один адрес, без порта.
func TestAskSetupAddsDefaultPort(t *testing.T) {
	withStdin(t, "192.168.1.10\nКОД\ny\n")

	server, _, ok := askSetup("", "")
	if !ok {
		t.Fatal("диалог не завершился успехом")
	}
	if server != "http://192.168.1.10:8765" {
		t.Errorf("адрес %q, ожидался с портом по умолчанию", server)
	}
}

// TestAskSetupRepeatsOnEmpty — пустой ответ не должен проходить дальше:
// агент с пустым адресом ушёл бы искать сервер на этой же машине.
func TestAskSetupRepeatsOnEmpty(t *testing.T) {
	output := withStdin(t, "\n\n192.168.1.10:8765\nКОД\n\n")

	server, _, ok := askSetup("", "")
	if !ok {
		t.Fatal("диалог не завершился успехом после повторного вопроса")
	}
	if server != "http://192.168.1.10:8765" {
		t.Errorf("адрес %q", server)
	}
	if out := output(); !strings.Contains(out, "Значение обязательно") {
		t.Errorf("пустой ответ не был отвергнут:\n%s", out)
	}
}

// TestAskSetupGivesUpOnClosedInput — если спрашивать не у кого, диалог обязан
// закончиться, а не крутиться вечно и не принять пустоту за ответ.
func TestAskSetupGivesUpOnClosedInput(t *testing.T) {
	withStdin(t, "")

	if _, _, ok := askSetup("", ""); ok {
		t.Error("при закрытом вводе диалог отчитался успехом")
	}
}

// TestAskSetupRespectsRefusal — «нет» на подтверждении отменяет установку.
func TestAskSetupRespectsRefusal(t *testing.T) {
	withStdin(t, "192.168.1.10:8765\nКОД\nn\n")

	if _, _, ok := askSetup("", ""); ok {
		t.Error("отказ на подтверждении не остановил установку")
	}
}

// TestAskSetupPromptsAreUnderstandable — диалог читает человек, который видит
// продукт впервые: в вопросах должны быть примеры, а не имена переменных.
func TestAskSetupPromptsAreUnderstandable(t *testing.T) {
	output := withStdin(t, "192.168.1.10\nКОД\n\n")
	askSetup("", "")

	out := output()
	for _, want := range []string{"Адрес сервера", "192.168.1.10:8765", "Код регистрации", "Настройки"} {
		if !strings.Contains(out, want) {
			t.Errorf("в диалоге нет %q:\n%s", want, out)
		}
	}
}

// Файл, отданный сервером уже настроенным, не должен ничего спрашивать: ради
// этого он и делался. Ввод здесь — один Enter на подтверждение; будь вопросы
// на месте, его съел бы первый из них и диалог отменился бы.
func TestAskSetupSkipsQuestionsWhenBaked(t *testing.T) {
	out := withStdin(t, "\n")

	server, code, ok := askSetup("192.168.1.10:8765", "vshityj-kod")
	text := out()

	if !ok {
		t.Fatalf("установка отменена, хотя подтверждение дано:\n%s", text)
	}
	if server != "http://192.168.1.10:8765" {
		t.Errorf("адрес %q — вписанный в файл не применён", server)
	}
	if code != "vshityj-kod" {
		t.Errorf("код %q — вписанный в файл не применён", code)
	}
	if strings.Contains(text, "Адрес сервера (например") {
		t.Errorf("спрошен адрес, который уже известен:\n%s", text)
	}
	if strings.Contains(text, "Код регистрации:") {
		t.Errorf("спрошен код, который уже известен:\n%s", text)
	}
	// Откуда взялись значения — человек должен видеть: иначе непонятно, на
	// какой сервер его сейчас поставят и почему ничего не спросили.
	if !strings.Contains(text, "вписаны в этот файл") {
		t.Errorf("не сказано, что настройки пришли из файла:\n%s", text)
	}
}

// Половина известного — не повод молчать про вторую: без кода установка всё
// равно не состоится, и спросить его надо.
func TestAskSetupAsksWhenOnlyServerKnown(t *testing.T) {
	out := withStdin(t, "КОД-456\n\n")

	server, code, ok := askSetup("192.168.1.10:8765", "")
	text := out()

	if !ok {
		t.Fatalf("установка отменена:\n%s", text)
	}
	if code != "КОД-456" {
		t.Errorf("код %q — введённый не применён", code)
	}
	if server == "" {
		t.Error("адрес потерян")
	}
}

func TestConfirmRegistrationChangeOffersPreserveAndTransfer(t *testing.T) {
	for _, tc := range []struct {
		input          string
		transfer, keep bool
		ok             bool
	}{{"1\n", false, true, true}, {"2\n", true, false, true}, {"\n", false, false, false}, {"3\n", false, false, false}} {
		t.Run(tc.input, func(t *testing.T) {
			dir := t.TempDir()
			writeInstallFixture(t, dir, agentConfig{ServerURL: "http://old:8765"}, agentState{DeviceID: 42, DeviceToken: "dpapi:opaque"})
			out := withStdin(t, tc.input)
			transfer, keep, ok := confirmRegistrationChange(dir, "new")
			text := out()
			if transfer != tc.transfer || keep != tc.keep || ok != tc.ok {
				t.Fatalf("wrong choice result: transfer=%v keep=%v ok=%v", transfer, keep, ok)
			}
			if !strings.Contains(text, "сохранить регистрацию") || !strings.Contains(text, "другой сервер") {
				t.Fatalf("choice must explain effect on registration:\n%s", text)
			}
			_, state, err := readInstallIdentity(dir)
			if err != nil || state.DeviceID != 42 || state.DeviceToken != "dpapi:opaque" {
				t.Fatalf("confirmation itself changed old identity: %+v %v", state, err)
			}
		})
	}
}

func TestConfirmRegistrationChangeSameServerNeedsNoExtraPrompt(t *testing.T) {
	dir := t.TempDir()
	writeInstallFixture(t, dir, agentConfig{ServerURL: "http://SERVER:8765/"}, agentState{DeviceID: 42, DeviceToken: "dpapi:opaque"})
	out := withStdin(t, "")
	transfer, keep, ok := confirmRegistrationChange(dir, "server")
	if transfer || keep || !ok || out() != "" {
		t.Fatalf("reinstall must preserve identity without another question: transfer=%v keep=%v ok=%v", transfer, keep, ok)
	}
}
