package auth

import (
	"encoding/base32"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTOTPReferenceVectorsAndReplayWindow(t *testing.T) {
	key := []byte("12345678901234567890")
	for i, want := range []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"} {
		if got := hotp(key, int64(i), 6); got != want {
			t.Fatalf("RFC 4226 counter %d: %s != %s", i, got, want)
		}
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
	for _, v := range []struct {
		second int64
		want   string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		if got := hotp(key, v.second/30, 8); got != v.want {
			t.Fatalf("RFC 6238 time %d: %s", v.second, got)
		}
	}
	now := time.Unix(1234567890, 0)
	for delta := int64(-2); delta <= 2; delta++ {
		candidate := now.Unix()/30 + delta
		code := hotp(key, candidate, 6)
		got, ok := totpStep(secret, code, now, -1)
		if ok != (delta >= -1 && delta <= 1) || (ok && got != candidate) {
			t.Fatalf("clock window %d: %d %t", delta, got, ok)
		}
		if _, ok := totpStep(secret, code, now, candidate); ok {
			t.Fatal("reused factor accepted")
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "１２３４５６", "12x456", "<script>"} {
		if _, ok := totpStep(secret, bad, now, -1); ok {
			t.Fatalf("malformed code accepted: %q", bad)
		}
	}
}

func mfaFixture(t *testing.T) (*MFA, int64, string, string) {
	t.Helper()
	d := testDB(t)
	id := newUser(t, d, "mfa-user", "admin")
	session, err := CreateSession(d, id)
	if err != nil {
		t.Fatal(err)
	}
	var hash string
	if err = d.QueryRow("SELECT password_hash FROM users WHERE id=?", id).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1900000000, 0)
	m := &MFA{DB: d, KeyPath: filepath.Join(t.TempDir(), "mfa.key"), Now: func() time.Time { return now }}
	return m, id, session, hash
}

func enableMFAFixture(t *testing.T, m *MFA, id int64, session, hash string) (string, MFAResult) {
	t.Helper()
	if err := m.BeginSetup(id, session, hash); err != nil {
		t.Fatal(err)
	}
	state, err := m.Status(id, session)
	if err != nil || state.Enabled || state.SetupSecret == "" {
		t.Fatalf("draft: %+v %v", state, err)
	}
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(state.SetupSecret)
	result, err := m.Enable(id, session, hotp(key, m.now().Unix()/30, 6))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RecoveryCodes) != 10 || result.Session == "" {
		t.Fatalf("enable result: %+v", result)
	}
	return state.SetupSecret, result
}

func TestMFASetupBoundToSessionConfirmedAndSecretsProtected(t *testing.T) {
	m, id, session, hash := mfaFixture(t)
	if _, err := os.Stat(m.KeyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("key created by status-less fixture")
	}
	if err := m.BeginSetup(id, session, hash); err != nil {
		t.Fatal(err)
	}
	state, err := m.Status(id, session)
	if err != nil || state.Enabled || len(state.SetupSecret) != 32 {
		t.Fatalf("draft: %+v %v", state, err)
	}
	other, _ := CreateSession(m.DB, id)
	second, err := m.Status(id, other)
	if err != nil || second.SetupSecret != "" {
		t.Fatal("draft secret leaked to another session")
	}
	if _, err := m.Enable(id, other, "123456"); !errors.Is(err, ErrMFAState) {
		t.Fatalf("other session enabled draft: %v", err)
	}
	var stored string
	if err := m.DB.QueryRow("SELECT secret FROM mfa_accounts WHERE user_id=?", id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == state.SetupSecret || strings.Contains(stored, state.SetupSecret) {
		t.Fatal("plaintext TOTP secret stored")
	}
	if _, err := m.unseal(id+1, stored); err == nil {
		t.Fatal("encrypted factor transferable to another user")
	}
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(state.SetupSecret)
	result, err := m.Enable(id, session, hotp(key, m.now().Unix()/30, 6))
	if err != nil {
		t.Fatal(err)
	}
	if CurrentUser(m.DB, reqWith(session)) != nil || CurrentUser(m.DB, reqWith(other)) != nil || CurrentUser(m.DB, reqWith(result.Session)) == nil {
		t.Fatal("session revocation/renewal failed")
	}
	state, err = m.Status(id, result.Session)
	if err != nil || !state.Enabled || state.SetupSecret != "" || state.RecoveryLeft != 10 {
		t.Fatalf("enabled state: %+v %v", state, err)
	}
	var recoveryHash string
	if err := m.DB.QueryRow("SELECT code_hash FROM mfa_recovery WHERE user_id=? LIMIT 1", id).Scan(&recoveryHash); err != nil {
		t.Fatal(err)
	}
	for _, code := range result.RecoveryCodes {
		if recoveryHash == normalizeRecovery(code) {
			t.Fatal("plaintext recovery code stored")
		}
	}
}

func TestMFAChallengeFactorReplayAndCredentialChange(t *testing.T) {
	m, id, session, hash := mfaFixture(t)
	secret, _ := enableMFAFixture(t, m, id, session, hash)
	if _, err := CreateSession(m.DB, id); !errors.Is(err, ErrMFAState) {
		t.Fatalf("password-only session bypassed enabled MFA: %v", err)
	}
	if _, err := CreatePasswordSession(m.DB, id, hash); !errors.Is(err, ErrMFAState) {
		t.Fatalf("first-factor session issued after MFA activation: %v", err)
	}
	token, err := m.BeginChallenge(id, hash)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := m.DB.QueryRow("SELECT token_hash FROM mfa_challenges").Scan(&stored); err != nil || stored == token {
		t.Fatal("plaintext login challenge stored")
	}
	if _, _, err := m.Challenge(stored); !errors.Is(err, ErrMFAExpired) {
		t.Fatal("challenge hash usable as cookie")
	}
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if _, _, _, err = m.FinishChallenge(token, hotp(key, m.now().Unix()/30, 6)); !errors.Is(err, ErrMFACode) {
		t.Fatalf("setup factor replay: %v", err)
	}
	now := m.now().Add(30 * time.Second)
	m.Now = func() time.Time { return now }
	_, _, login, err := m.FinishChallenge(token, hotp(key, now.Unix()/30, 6))
	if err != nil || login == "" {
		t.Fatalf("valid TOTP login: %v", err)
	}
	if _, _, _, err = m.FinishChallenge(token, hotp(key, now.Unix()/30, 6)); !errors.Is(err, ErrMFAExpired) {
		t.Fatal("completed challenge reused")
	}
	next, err := m.BeginChallenge(id, hash)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = m.FinishChallenge(next, hotp(key, now.Unix()/30, 6)); !errors.Is(err, ErrMFACode) {
		t.Fatal("TOTP reused across challenges")
	}
	newHash, _ := HashPassword("Drugojparol2")
	if err := UpdatePassword(m.DB, id, hash, newHash, login); err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.Challenge(next); !errors.Is(err, ErrMFAExpired) {
		t.Fatal("password update kept pending first-factor approval")
	}
	if CurrentUser(m.DB, reqWith(login)) == nil {
		t.Fatal("password change removed current session")
	}
	enabled, err := m.Enabled(id)
	if err != nil || !enabled {
		t.Fatal("password change silently disabled MFA")
	}
}

func TestMFAPersistentLockoutCannotBeResetWithNewChallenge(t *testing.T) {
	m, id, session, hash := mfaFixture(t)
	_, result := enableMFAFixture(t, m, id, session, hash)
	for i := 0; i < 5; i++ {
		challenge, err := m.BeginChallenge(id, hash)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, err = m.FinishChallenge(challenge, "not-a-code")
		if i < 4 && !errors.Is(err, ErrMFACode) {
			t.Fatalf("failure %d: %v", i, err)
		}
		if i == 4 && !errors.Is(err, ErrMFALocked) {
			t.Fatalf("lock: %v", err)
		}
	}
	restart := &MFA{DB: m.DB, KeyPath: m.KeyPath, Now: m.Now}
	if _, err := restart.BeginChallenge(id, hash); !errors.Is(err, ErrMFALocked) {
		t.Fatalf("restart bypassed lockout: %v", err)
	}
	now := m.now().Add(301 * time.Second)
	m.Now = func() time.Time { return now }
	challenge, err := m.BeginChallenge(id, hash)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := m.FinishChallenge(challenge, result.RecoveryCodes[0]); err != nil {
		t.Fatalf("recovery after cooldown: %v", err)
	}
}

func TestMFARecoverySingleUseRegenerationAndMissingKey(t *testing.T) {
	m, id, session, hash := mfaFixture(t)
	_, result := enableMFAFixture(t, m, id, session, hash)
	if err := os.Remove(m.KeyPath); err != nil {
		t.Fatal(err)
	}
	challenge, err := m.BeginChallenge(id, hash)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = m.FinishChallenge(challenge, result.RecoveryCodes[0])
	if err != nil {
		t.Fatalf("recovery must survive loss of encryption key: %v", err)
	}
	if _, err := m.key(true); err == nil {
		t.Fatal("missing key regenerated over enrolled users")
	}
	if _, err := os.Stat(m.KeyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("login created a replacement key")
	}
	regenerated, err := m.Change(id, hash, result.RecoveryCodes[1], false)
	if err != nil || len(regenerated.RecoveryCodes) != 10 {
		t.Fatalf("regenerate recovery: %v", err)
	}
	challenge, _ = m.BeginChallenge(id, hash)
	if _, _, _, err := m.FinishChallenge(challenge, result.RecoveryCodes[2]); !errors.Is(err, ErrMFACode) {
		t.Fatal("old recovery set survived regeneration")
	}
	disabled, err := m.Change(id, hash, regenerated.RecoveryCodes[0], true)
	if err != nil || disabled.Session == "" {
		t.Fatalf("disable using recovery: %v", err)
	}
	if enabled, err := m.Enabled(id); err != nil || enabled {
		t.Fatal("MFA not disabled")
	}
}

func TestMFARecoveryCannotBeUsedTwiceConcurrently(t *testing.T) {
	m, id, session, hash := mfaFixture(t)
	_, result := enableMFAFixture(t, m, id, session, hash)
	a, _ := m.BeginChallenge(id, hash)
	b, _ := m.BeginChallenge(id, hash)
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for _, challenge := range []string{a, b} {
		wg.Add(1)
		go func(token string) {
			defer wg.Done()
			_, _, _, err := m.FinishChallenge(token, result.RecoveryCodes[0])
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}(challenge)
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("same recovery code authenticated %d concurrent logins", successes)
	}
}

func TestMFADisabledAccountExpiredDraftAndChallenge(t *testing.T) {
	m, id, session, hash := mfaFixture(t)
	if err := m.BeginSetup(id, session, hash); err != nil {
		t.Fatal(err)
	}
	now := m.now().Add(601 * time.Second)
	m.Now = func() time.Time { return now }
	if _, err := m.Enable(id, session, "123456"); !errors.Is(err, ErrMFAExpired) {
		t.Fatal("expired setup activated")
	}
	if err := m.CancelSetup(id, session); err != nil {
		t.Fatal(err)
	}
	_, result := enableMFAFixture(t, m, id, session, hash)
	challenge, _ := m.BeginChallenge(id, hash)
	now = now.Add(301 * time.Second)
	if _, _, _, err := m.FinishChallenge(challenge, result.RecoveryCodes[0]); !errors.Is(err, ErrMFAExpired) {
		t.Fatal("expired challenge authenticated")
	}
	challenge, _ = m.BeginChallenge(id, hash)
	if _, err := m.DB.Exec("UPDATE users SET is_active=0 WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := m.FinishChallenge(challenge, result.RecoveryCodes[0]); !errors.Is(err, ErrMFAExpired) {
		t.Fatal("disabled account authenticated")
	}
}
