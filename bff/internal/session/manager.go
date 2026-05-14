package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

const sessionTTL = 24 * time.Hour

type Manager struct {
	store          Store
	cookieName     string
	insecureCookie bool
}

func NewManager(store Store, cookieName, secret string, insecureCookie bool) *Manager {
	_ = secret
	return &Manager{store: store, cookieName: cookieName, insecureCookie: insecureCookie}
}

func (m *Manager) Create(w http.ResponseWriter, s Session) error {
	id, err := randomToken(32)
	if err != nil {
		return err
	}

	if err := m.store.Put(context.Background(), id, s, sessionTTL); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   !m.insecureCookie,
		MaxAge:   int(sessionTTL.Seconds()),
	})

	return nil
}

func (m *Manager) Get(r *http.Request) (Session, bool, error) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return Session{}, false, nil
		}
		return Session{}, false, err
	}

	id := strings.TrimSpace(cookie.Value)
	if id == "" {
		return Session{}, false, nil
	}

	return m.store.Get(r.Context(), id)
}

func (m *Manager) Destroy(w http.ResponseWriter, r *http.Request) error {
	cookie, err := r.Cookie(m.cookieName)
	if err == nil && strings.TrimSpace(cookie.Value) != "" {
		if delErr := m.store.Delete(r.Context(), cookie.Value); delErr != nil {
			return delErr
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   !m.insecureCookie,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})

	return nil
}

func randomToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
