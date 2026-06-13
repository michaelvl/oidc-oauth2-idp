package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const maxCookieValueBytes = 3900

type CookieStore struct {
	key [32]byte
}

func NewCookieStore(secret string) *CookieStore {
	return &CookieStore{key: sha256.Sum256([]byte(secret))}
}

func (c *CookieStore) Save(_ context.Context, s Session, _ time.Duration) (string, error) {
	plaintext, err := json.Marshal(s)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(c.key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	token := base64.RawURLEncoding.EncodeToString(ciphertext)

	if len(token) > maxCookieValueBytes {
		return "", fmt.Errorf("encrypted session exceeds cookie size limit (%d bytes); use server-side session storage instead", maxCookieValueBytes)
	}

	return token, nil
}

func (c *CookieStore) Load(_ context.Context, token string) (Session, bool, error) {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Session{}, false, nil
	}

	block, err := aes.NewCipher(c.key[:])
	if err != nil {
		return Session{}, false, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Session{}, false, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return Session{}, false, nil
	}

	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return Session{}, false, nil
	}

	var s Session
	if err := json.Unmarshal(plaintext, &s); err != nil {
		return Session{}, false, err
	}

	return s, true, nil
}

func (c *CookieStore) Delete(_ context.Context, _ string) error {
	return nil
}
