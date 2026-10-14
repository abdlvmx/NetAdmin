package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // RFC 6238 provisioning profile: SHA-1, six digits, 30 seconds.
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrMFACode    = errors.New("invalid or already used second factor")
	ErrMFALocked  = errors.New("second factor temporarily locked")
	ErrMFAExpired = errors.New("second factor setup or challenge expired")
	ErrMFAState   = errors.New("second factor state changed")
	mfaKeyMu      sync.Mutex
)

// MFA stores encrypted TOTP secrets in the database, with a separate server key.
// No key is created by login, status reads or recovery-code authentication.
type MFA struct {
	DB      *sql.DB
	KeyPath string
	Now     func() time.Time
}

type MFAStatus struct {
	Enabled      bool
	RecoveryLeft int
	SetupSecret  string
}

type MFAResult struct {
	Session       string
	RecoveryCodes []string
}

func (m *MFA) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *MFA) Enabled(id int64) (bool, error) {
	var enabled int
	err := m.DB.QueryRow("SELECT enabled FROM mfa_accounts WHERE user_id=?", id).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err == nil && enabled != 0 && enabled != 1 {
		return false, ErrMFAState
	}
	return enabled == 1, err
}

func (m *MFA) key(create bool) ([]byte, error) {
	mfaKeyMu.Lock()
	defer mfaKeyMu.Unlock()
	info, err := os.Lstat(m.KeyPath)
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() != 32 {
			return nil, errors.New("invalid MFA key file")
		}
		if err := protectMFAKey(m.KeyPath); err != nil {
			return nil, errors.New("cannot protect MFA key")
		}
		b, err := os.ReadFile(m.KeyPath)
		if err != nil || len(b) != 32 {
			return nil, errors.New("MFA key unavailable")
		}
		return b, nil
	}
	if !create || !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("MFA key unavailable")
	}
	var existing int
	if err := m.DB.QueryRow("SELECT COUNT(*) FROM mfa_accounts").Scan(&existing); err != nil {
		return nil, err
	}
	if existing != 0 {
		return nil, errors.New("MFA key missing; restore the original key")
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(m.KeyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	// Restrict access before any key bytes reach the file.
	writeErr := protectMFAKey(m.KeyPath)
	if writeErr == nil {
		_, writeErr = f.Write(key)
	}
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(m.KeyPath)
		return nil, errors.New("cannot save MFA key")
	}
	return key, nil
}

func (m *MFA) seal(id int64, secret string) (string, error) {
	key, err := m.key(true)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	b := gcm.Seal(nonce, nonce, []byte(secret), []byte("NetAdmin MFA:"+strconv.FormatInt(id, 10)))
	return "v1:" + base64.RawStdEncoding.EncodeToString(b), nil
}

func (m *MFA) unseal(id int64, sealed string) (string, error) {
	if !strings.HasPrefix(sealed, "v1:") {
		return "", errors.New("invalid encrypted MFA secret")
	}
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(sealed, "v1:"))
	if err != nil {
		return "", errors.New("invalid encrypted MFA secret")
	}
	key, err := m.key(false)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(b) < gcm.NonceSize()+gcm.Overhead() {
		return "", errors.New("invalid encrypted MFA secret")
	}
	plain, err := gcm.Open(nil, b[:gcm.NonceSize()], b[gcm.NonceSize():], []byte("NetAdmin MFA:"+strconv.FormatInt(id, 10)))
	if err != nil {
		return "", errors.New("cannot decrypt MFA secret")
	}
	return string(plain), nil
}

func (m *MFA) Status(id int64, session string) (MFAStatus, error) {
	var s MFAStatus
	var enabled int
	var secret, bound string
	var expires int64
	err := m.DB.QueryRow("SELECT enabled,secret,setup_session,setup_expires FROM mfa_accounts WHERE user_id=?", id).Scan(&enabled, &secret, &bound, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	s.Enabled = enabled == 1
	if s.Enabled {
		err = m.DB.QueryRow("SELECT COUNT(*) FROM mfa_recovery WHERE user_id=?", id).Scan(&s.RecoveryLeft)
		if err == nil {
			_, err = m.unseal(id, secret)
		}
	} else if session != "" && bound == hashToken(session) && expires > m.now().Unix() {
		s.SetupSecret, err = m.unseal(id, secret)
	}
	return s, err
}

// BeginSetup requires a recently checked password and binds the draft to this
// session and password hash. A second session cannot read or activate the draft.
func (m *MFA) BeginSetup(id int64, session, passwordHash string) error {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	sealed, err := m.seal(id, secret)
	if err != nil {
		return err
	}
	result, err := m.DB.Exec(`INSERT INTO mfa_accounts(user_id,secret,setup_session,setup_password,setup_expires)
        SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.id=? AND u.password_hash=? AND u.is_active=1 AND s.token=?)
        ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret,setup_session=excluded.setup_session,setup_password=excluded.setup_password,setup_expires=excluded.setup_expires
        WHERE mfa_accounts.enabled=0`, id, sealed, hashToken(session), passwordHash, m.now().Add(10*time.Minute).Unix(), id, passwordHash, hashToken(session))
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return ErrMFAState
	}
	return err
}

func (m *MFA) CancelSetup(id int64, session string) error {
	_, err := m.DB.Exec("DELETE FROM mfa_accounts WHERE user_id=? AND enabled=0 AND setup_session=?", id, hashToken(session))
	return err
}

func ProvisioningURI(username, secret string) string {
	values := url.Values{"secret": {secret}, "issuer": {"NetAdmin"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape("NetAdmin:"+username) + "?" + values.Encode()
}

func hotp(secret []byte, step int64, digits int) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	h := hmac.New(sha1.New, secret)
	_, _ = h.Write(counter[:])
	digest := h.Sum(nil)
	offset := int(digest[len(digest)-1] & 15)
	number := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	divisor := uint32(1000000)
	if digits == 8 {
		divisor = 100000000
	}
	return fmt.Sprintf("%0*d", digits, number%divisor)
}

func totpStep(secret, code string, now time.Time, last int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) < 20 {
		return 0, false
	}
	step := now.Unix() / 30
	found := int64(-1)
	for _, candidate := range []int64{step - 1, step, step + 1} {
		if candidate < 0 || candidate <= last {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, candidate, 6)), []byte(code)) == 1 {
			found = candidate
		}
	}
	return found, found >= 0
}

func normalizeRecovery(code string) string {
	code = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if len(code) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(code); err != nil {
		return ""
	}
	return code
}

func recoveryCodes(tx *sql.Tx, id int64) ([]string, error) {
	if _, err := tx.Exec("DELETE FROM mfa_recovery WHERE user_id=?", id); err != nil {
		return nil, err
	}
	codes := make([]string, 0, 10)
	for range 10 {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		raw := hex.EncodeToString(b)
		if _, err := tx.Exec("INSERT INTO mfa_recovery(user_id,code_hash) VALUES(?,?)", id, hashToken(raw)); err != nil {
			return nil, err
		}
		codes = append(codes, raw[:8]+"-"+raw[8:16]+"-"+raw[16:24]+"-"+raw[24:])
	}
	return codes, nil
}

func (m *MFA) allowed(tx *sql.Tx, id int64) error {
	var until int64
	if err := tx.QueryRow("SELECT blocked_until FROM mfa_accounts WHERE user_id=?", id).Scan(&until); err != nil {
		return err
	}
	if until > m.now().Unix() {
		return ErrMFALocked
	}
	return nil
}

// Failed attempts persist across new challenges and server restarts.
func (m *MFA) failed(tx *sql.Tx, id int64) error {
	var failures int
	var last int64
	if err := tx.QueryRow("SELECT failures,last_failure FROM mfa_accounts WHERE user_id=?", id).Scan(&failures, &last); err != nil {
		return err
	}
	now := m.now().Unix()
	if now-last >= 300 {
		failures = 0
	}
	failures++
	until := int64(0)
	if failures >= 5 {
		until = now + 300
	}
	if _, err := tx.Exec("UPDATE mfa_accounts SET failures=?,last_failure=?,blocked_until=? WHERE user_id=?", failures, now, until, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if until > 0 {
		return ErrMFALocked
	}
	return ErrMFACode
}

func (m *MFA) consume(tx *sql.Tx, id int64, sealed string, last int64, code string) (bool, error) {
	if raw := normalizeRecovery(code); raw != "" {
		result, err := tx.Exec("DELETE FROM mfa_recovery WHERE user_id=? AND code_hash=?", id, hashToken(raw))
		if err != nil {
			return false, err
		}
		n, err := result.RowsAffected()
		return n == 1, err
	}
	secret, err := m.unseal(id, sealed)
	if err != nil {
		return false, err
	}
	step, ok := totpStep(secret, code, m.now(), last)
	if !ok {
		return false, nil
	}
	result, err := tx.Exec("UPDATE mfa_accounts SET last_step=? WHERE user_id=? AND last_step=? AND enabled=1 AND secret=?", step, id, last, sealed)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func resetFactors(tx *sql.Tx, id int64) error {
	_, err := tx.Exec("UPDATE mfa_accounts SET failures=0,last_failure=0,blocked_until=0 WHERE user_id=?", id)
	return err
}

func replaceSessions(tx *sql.Tx, id int64) (string, error) {
	if _, err := tx.Exec("DELETE FROM sessions WHERE user_id=?", id); err != nil {
		return "", err
	}
	if _, err := tx.Exec("DELETE FROM mfa_challenges WHERE user_id=?", id); err != nil {
		return "", err
	}
	return createSession(tx, id)
}

func (m *MFA) Enable(id int64, session, code string) (MFAResult, error) {
	var result MFAResult
	tx, err := m.DB.Begin()
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var sealed string
	var expires int64
	err = tx.QueryRow(`SELECT m.secret,m.setup_expires FROM mfa_accounts m JOIN users u ON u.id=m.user_id JOIN sessions s ON s.user_id=u.id
        WHERE m.user_id=? AND m.enabled=0 AND m.setup_session=? AND u.is_active=1 AND u.password_hash=m.setup_password AND s.token=?`, id, hashToken(session), hashToken(session)).Scan(&sealed, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrMFAState
	}
	if err != nil {
		return result, err
	}
	if expires <= m.now().Unix() {
		return result, ErrMFAExpired
	}
	if err = m.allowed(tx, id); err != nil {
		return result, err
	}
	secret, err := m.unseal(id, sealed)
	if err != nil {
		return result, err
	}
	step, ok := totpStep(secret, code, m.now(), -1)
	if !ok {
		return result, m.failed(tx, id)
	}
	if _, err = tx.Exec("UPDATE mfa_accounts SET enabled=1,setup_session='',setup_password='',setup_expires=0,last_step=?,failures=0,last_failure=0,blocked_until=0 WHERE user_id=?", step, id); err != nil {
		return result, err
	}
	result.RecoveryCodes, err = recoveryCodes(tx, id)
	if err == nil {
		result.Session, err = replaceSessions(tx, id)
	}
	if err != nil {
		return MFAResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return MFAResult{}, err
	}
	return result, nil
}

// Change handles disable and code regeneration after password reauthentication.
func (m *MFA) Change(id int64, passwordHash, code string, disable bool) (MFAResult, error) {
	var result MFAResult
	tx, err := m.DB.Begin()
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var sealed string
	var last int64
	err = tx.QueryRow(`SELECT m.secret,m.last_step FROM mfa_accounts m JOIN users u ON u.id=m.user_id WHERE m.user_id=? AND m.enabled=1 AND u.is_active=1 AND u.password_hash=?`, id, passwordHash).Scan(&sealed, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrMFAState
	}
	if err != nil {
		return result, err
	}
	if err = m.allowed(tx, id); err != nil {
		return result, err
	}
	ok, err := m.consume(tx, id, sealed, last, code)
	if err != nil {
		return result, err
	}
	if !ok {
		return result, m.failed(tx, id)
	}
	if disable {
		_, err = tx.Exec("DELETE FROM mfa_accounts WHERE user_id=?", id)
	} else {
		result.RecoveryCodes, err = recoveryCodes(tx, id)
		if err == nil {
			err = resetFactors(tx, id)
		}
	}
	if err == nil {
		result.Session, err = replaceSessions(tx, id)
	}
	if err != nil {
		return MFAResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return MFAResult{}, err
	}
	return result, nil
}

func (m *MFA) BeginChallenge(id int64, passwordHash string) (string, error) {
	token := randomHex(32)
	tx, err := m.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM mfa_challenges WHERE expires<=?", m.now().Unix()); err != nil {
		return "", err
	}
	var count int
	if err = tx.QueryRow("SELECT COUNT(*) FROM mfa_challenges").Scan(&count); err != nil {
		return "", err
	}
	if count >= 5000 {
		return "", errors.New("too many pending MFA logins")
	}
	if err = tx.QueryRow("SELECT COUNT(*) FROM mfa_challenges WHERE user_id=?", id).Scan(&count); err != nil {
		return "", err
	}
	if count >= 10 {
		return "", errors.New("too many pending logins for this account")
	}
	if err = m.allowed(tx, id); err != nil {
		return "", err
	}
	res, err := tx.Exec(`INSERT INTO mfa_challenges(token_hash,user_id,password_hash,secret,expires)
        SELECT ?,u.id,u.password_hash,m.secret,? FROM users u JOIN mfa_accounts m ON m.user_id=u.id WHERE u.id=? AND u.is_active=1 AND u.password_hash=? AND m.enabled=1`, hashToken(token), m.now().Add(5*time.Minute).Unix(), id, passwordHash)
	if err != nil {
		return "", err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	if n != 1 {
		return "", ErrMFAState
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

func (m *MFA) Challenge(token string) (int64, string, error) {
	var id int64
	var username string
	err := m.DB.QueryRow(`SELECT u.id,u.username FROM mfa_challenges c JOIN users u ON u.id=c.user_id JOIN mfa_accounts m ON m.user_id=u.id
        WHERE c.token_hash=? AND c.expires>? AND u.is_active=1 AND u.password_hash=c.password_hash AND m.enabled=1 AND m.secret=c.secret`, hashToken(token), m.now().Unix()).Scan(&id, &username)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrMFAExpired
	}
	return id, username, err
}

func (m *MFA) ForgetChallenge(token string) {
	_, _ = m.DB.Exec("DELETE FROM mfa_challenges WHERE token_hash=?", hashToken(token))
}

// FinishChallenge consumes the factor and issues the session in one transaction.
func (m *MFA) FinishChallenge(token, code string) (int64, string, string, error) {
	tx, err := m.DB.Begin()
	if err != nil {
		return 0, "", "", err
	}
	defer tx.Rollback()
	var id, last int64
	var username, sealed string
	err = tx.QueryRow(`SELECT u.id,u.username,m.secret,m.last_step FROM mfa_challenges c JOIN users u ON u.id=c.user_id JOIN mfa_accounts m ON m.user_id=u.id
        WHERE c.token_hash=? AND c.expires>? AND u.is_active=1 AND u.password_hash=c.password_hash AND m.enabled=1 AND m.secret=c.secret`, hashToken(token), m.now().Unix()).Scan(&id, &username, &sealed, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", "", ErrMFAExpired
	}
	if err != nil {
		return 0, "", "", err
	}
	if err = m.allowed(tx, id); err != nil {
		return id, username, "", err
	}
	ok, err := m.consume(tx, id, sealed, last, code)
	if err != nil {
		return id, username, "", err
	}
	if !ok {
		return id, username, "", m.failed(tx, id)
	}
	if err = resetFactors(tx, id); err != nil {
		return id, username, "", err
	}
	if _, err = tx.Exec("DELETE FROM mfa_challenges WHERE token_hash=?", hashToken(token)); err != nil {
		return id, username, "", err
	}
	session, err := createSession(tx, id)
	if err != nil {
		return id, username, "", err
	}
	if err = tx.Commit(); err != nil {
		return id, username, "", err
	}
	return id, username, session, nil
}
