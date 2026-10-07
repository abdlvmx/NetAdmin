package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"netadmin/internal/agentbin"
	"netadmin/internal/version"
)

//go:embed welcome.html
var welcomeHTML string
var welcomeTemplate = template.Must(template.New("welcome").Parse(welcomeHTML))

type welcomeResult struct {
	Choice   firstRunChoice
	Firewall firewallChoice
}
type welcomePage struct {
	Path, Token, Version, Message string
	CanInstall, CanAgent, Done    bool
}
type welcomeHandler struct {
	host, path, token    string
	canInstall, canAgent bool
	mu                   sync.Mutex
	chosen               bool
	result               chan welcomeResult
}

func (h *welcomeHandler) page(w http.ResponseWriter, message string, done bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = welcomeTemplate.Execute(w, welcomePage{
		Path: h.path, Token: h.token, Version: version.Value,
		CanInstall: h.canInstall, CanAgent: h.canAgent, Message: message, Done: done,
	})
}
func (h *welcomeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+h.token+"'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	// Exact loopback Host prevents DNS rebinding to this local launcher.
	if r.Host != h.host {
		http.Error(w, "Откройте адрес мастера, показанный в окне NetAdmin.", http.StatusForbidden)
		return
	}
	if r.URL.Path != h.path {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		h.mu.Lock()
		done := h.chosen
		h.mu.Unlock()
		h.page(w, "Действие уже выбрано. Следуйте указаниям в окне NetAdmin.", done)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Метод не поддерживается.", http.StatusMethodNotAllowed)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+h.host {
		http.Error(w, "Обновите страницу мастера и повторите действие.", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Не удалось прочитать выбор. Обновите страницу.", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("token")), []byte(h.token)) != 1 {
		http.Error(w, "Эта страница устарела. Откройте текущий мастер запуска.", http.StatusForbidden)
		return
	}
	result := welcomeResult{Firewall: firewallNo}
	var message string
	switch r.PostForm.Get("action") {
	case "demo":
		result.Choice, message = choiceDemo, "Запускаем пример. Панель откроется в новой вкладке; вход и пароль показаны в окне NetAdmin. Пока смотрите демо, оставьте это окно открытым."
	case "setup":
		result.Choice, message = choiceSetup, "Запускаем сервер. Панель откроется в новой вкладке: создайте учётную запись администратора. Сервер работает, пока окно NetAdmin открыто."
	case "install":
		if !h.canInstall {
			http.Error(w, "Постоянная установка доступна в Windows.", http.StatusBadRequest)
			return
		}
		result.Choice, message = choiceInstall, "Открываем установку. Подтвердите запрос прав Windows. После успешной установки откроется панель; ярлык NetAdmin появится на рабочем столе. При ошибке установщик покажет причину."
		if r.PostForm.Get("lan") == "yes" {
			result.Firewall = firewallYes
		}
	case "agent":
		if !h.canAgent {
			http.Error(w, "Агент недоступен. Скачайте готовый комплект Windows.", http.StatusBadRequest)
			return
		}
		result.Choice, message = choiceAgent, "Открываем установку агента в отдельном окне. Подтвердите запрос прав Windows и введите адрес и код, полученные от администратора. Подготовленный агент из панели сервера уже содержит эти сведения."
	case "quit":
		result.Choice, message = choiceQuit, "Мастер закрыт. Вы можете закрыть эту вкладку и снова запустить NetAdmin позже."
	default:
		http.Error(w, "Выберите одно из действий на странице.", http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.chosen {
		w.WriteHeader(http.StatusConflict)
		h.page(w, "Действие уже выбрано. Следуйте указаниям в окне NetAdmin.", true)
		return
	}
	h.chosen = true
	h.page(w, message, true)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	h.result <- result
}

// The loopback launcher shuts down before the selected installer or server runs.
func chooseWelcome(explicit bool) (welcomeResult, error) {
	if !explicit && os.Getenv("NETADMIN_NO_BROWSER") != "" {
		return welcomeResult{Choice: askFirstRun(), Firewall: firewallAsk}, nil
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return welcomeResult{}, err
	}
	defer listener.Close()
	var nonce [48]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return welcomeResult{}, err
	}
	h := &welcomeHandler{
		host:       listener.Addr().String(),
		path:       "/welcome/" + base64.RawURLEncoding.EncodeToString(nonce[:24]) + "/",
		token:      base64.RawURLEncoding.EncodeToString(nonce[24:]),
		canInstall: runtime.GOOS == "windows", canAgent: welcomeAgentAvailable(),
		result: make(chan welcomeResult, 1),
	}
	server := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	errorsCh := make(chan error, 1)
	go func() { errorsCh <- server.Serve(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	address := "http://" + h.host + h.path
	fmt.Println("\n  NetAdmin — мастер запуска")
	fmt.Println("  Выберите действие в браузере. Оставьте это окно открытым.")
	fmt.Println("  Если вкладка не появилась, откройте:", address)
	if os.Getenv("NETADMIN_NO_BROWSER") == "" {
		if err := launchBrowser(address); err != nil {
			fmt.Println("  Браузер не открылся автоматически:", err)
			fmt.Println("  Скопируйте адрес выше и откройте его в браузере вручную.")
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	timer := time.NewTimer(30 * time.Minute)
	defer timer.Stop()
	select {
	case result := <-h.result:
		return result, nil
	case <-ctx.Done():
		return welcomeResult{Choice: choiceQuit}, nil
	case <-timer.C:
		fmt.Println("  Мастер закрыт после 30 минут без выбора. Запустите NetAdmin снова.")
		return welcomeResult{Choice: choiceQuit}, nil
	case err := <-errorsCh:
		if errors.Is(err, http.ErrServerClosed) {
			return welcomeResult{Choice: choiceQuit}, nil
		}
		return welcomeResult{}, err
	}
}

func welcomeAgentAvailable() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	if agentbin.Available() {
		return true
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	st, err := os.Stat(filepath.Join(filepath.Dir(exe), "agent.exe"))
	return err == nil && st.Mode().IsRegular()
}
func launchWelcomeAgent() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("агент предназначен для Windows")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(exe), "agent.exe")
	// Prefer the current embedded build over a leftover sibling from an old ZIP.
	if data, _, ok := agentbin.Bytes(); ok {
		cache, err := os.UserCacheDir()
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		dir := filepath.Join(cache, "NetAdmin", fmt.Sprintf("agent-setup-%x", sum[:8]))
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		path = filepath.Join(dir, "agent.exe")
		if existing, err := os.ReadFile(path); err != nil || sha256.Sum256(existing) != sum {
			if err := os.WriteFile(path, data, 0600); err != nil {
				return err
			}
		}
	} else if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("agent.exe отсутствует; скачайте готовый комплект Windows или подготовленный агент у администратора")
	}
	return startAgentSetup(path)
}
