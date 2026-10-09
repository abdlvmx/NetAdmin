package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type TLSSettings struct {
	CertFile  string
	KeyFile   string
	PublicURL string
}

func (s TLSSettings) Enabled() bool { return s.CertFile != "" || s.KeyFile != "" }

// TLSSettingsAt uses the data directory, never the SCM working directory.
// Install probes deliberately ignore the installer's shell environment.
func (c Config) TLSSettingsAt(dir string, useEnv bool) (TLSSettings, error) {
	s := TLSSettings{strings.TrimSpace(c.TLSCertFile), strings.TrimSpace(c.TLSKeyFile), strings.TrimSpace(c.PublicURL)}
	if useEnv {
		for name, target := range map[string]*string{"NETADMIN_TLS_CERT": &s.CertFile, "NETADMIN_TLS_KEY": &s.KeyFile, "NETADMIN_PUBLIC_URL": &s.PublicURL} {
			if v := strings.TrimSpace(os.Getenv(name)); v != "" {
				*target = v
			}
		}
	}
	if !s.Enabled() {
		if s.PublicURL != "" {
			return s, errors.New("public_url задаётся вместе с сертификатом и ключом HTTPS")
		}
		return s, nil
	}
	if s.CertFile == "" || s.KeyFile == "" {
		return s, errors.New("для HTTPS задайте tls_cert_file и tls_key_file")
	}
	if s.PublicURL == "" {
		return s, errors.New("для HTTPS задайте public_url: https://имя-сервера:порт, соответствующий сертификату")
	}
	u, err := url.Parse(s.PublicURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return s, errors.New("public_url должен быть HTTPS-адресом сервера без пароля, пути и параметров")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return s, errors.New("порт public_url должен быть в диапазоне 1–65535")
		}
	}
	s.PublicURL = strings.TrimRight(s.PublicURL, "/")
	if !filepath.IsAbs(s.CertFile) {
		s.CertFile = filepath.Join(dir, s.CertFile)
	}
	if !filepath.IsAbs(s.KeyFile) {
		s.KeyFile = filepath.Join(dir, s.KeyFile)
	}
	return s, nil
}

func (s TLSSettings) Load() (*tls.Config, error) {
	if !s.Enabled() {
		return nil, nil
	}
	pair, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("сертификат или ключ HTTPS: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("сертификат HTTPS: %w", err)
	}
	u, err := url.Parse(s.PublicURL)
	if err != nil {
		return nil, err
	}
	if err = leaf.VerifyHostname(u.Hostname()); err != nil {
		return nil, fmt.Errorf("сертификат не соответствует public_url: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("срок действия сертификата HTTPS ещё не начался или уже истёк")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, nil
}
