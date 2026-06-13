package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type Store interface {
	Save(ctx context.Context, s Session, ttl time.Duration) (string, error)
	Load(ctx context.Context, token string) (Session, bool, error)
	Delete(ctx context.Context, token string) error
}

func randomToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptAESGCM(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
}

type MemoryStore struct {
	mu    sync.RWMutex
	items map[string]memoryItem
}

type memoryItem struct {
	session Session
	expires time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: make(map[string]memoryItem)}
}

func (m *MemoryStore) Save(_ context.Context, s Session, ttl time.Duration) (string, error) {
	id, err := randomToken(32)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[id] = memoryItem{session: s, expires: time.Now().Add(ttl)}
	return id, nil
}

func (m *MemoryStore) Load(_ context.Context, token string) (Session, bool, error) {
	m.mu.RLock()
	item, ok := m.items[token]
	m.mu.RUnlock()
	if !ok {
		return Session{}, false, nil
	}
	if time.Now().After(item.expires) {
		m.mu.Lock()
		delete(m.items, token)
		m.mu.Unlock()
		return Session{}, false, nil
	}
	return item.session, true, nil
}

func (m *MemoryStore) Delete(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, token)
	return nil
}

type RedisStore struct {
	client *redis.Client
	prefix string
}

func NewRedisStore(redisURL, cookieName string) (*RedisStore, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	return &RedisStore{
		client: redis.NewClient(opt),
		prefix: cookieName + "-",
	}, nil
}

func (r *RedisStore) Save(ctx context.Context, s Session, ttl time.Duration) (string, error) {
	id, err := randomToken(32)
	if err != nil {
		return "", err
	}

	secretBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secretBytes); err != nil {
		return "", err
	}

	plaintext, err := json.Marshal(s)
	if err != nil {
		return "", err
	}

	ciphertext, err := encryptAESGCM(secretBytes, plaintext)
	if err != nil {
		return "", err
	}

	if err := r.client.Set(ctx, r.prefix+id, ciphertext, ttl).Err(); err != nil {
		return "", err
	}

	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	return id + "." + secret, nil
}

func (r *RedisStore) Load(ctx context.Context, token string) (Session, bool, error) {
	id, secretB64, ok := strings.Cut(token, ".")
	if !ok {
		return Session{}, false, nil
	}

	secretBytes, err := base64.RawURLEncoding.DecodeString(secretB64)
	if err != nil {
		return Session{}, false, nil
	}

	ciphertext, err := r.client.Get(ctx, r.prefix+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}

	plaintext, err := decryptAESGCM(secretBytes, ciphertext)
	if err != nil {
		return Session{}, false, nil
	}

	var s Session
	if err := json.Unmarshal(plaintext, &s); err != nil {
		return Session{}, false, err
	}

	return s, true, nil
}

func (r *RedisStore) Delete(ctx context.Context, token string) error {
	id, _, _ := strings.Cut(token, ".")
	return r.client.Del(ctx, r.prefix+id).Err()
}
