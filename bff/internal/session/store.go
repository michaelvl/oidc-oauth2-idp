package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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

func NewRedisStore(redisURL string) (*RedisStore, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	return &RedisStore{
		client: redis.NewClient(opt),
		prefix: "session:",
	}, nil
}

func (r *RedisStore) Save(ctx context.Context, s Session, ttl time.Duration) (string, error) {
	id, err := randomToken(32)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	if err := r.client.Set(ctx, r.prefix+id, string(b), ttl).Err(); err != nil {
		return "", err
	}
	return id, nil
}

func (r *RedisStore) Load(ctx context.Context, token string) (Session, bool, error) {
	raw, err := r.client.Get(ctx, r.prefix+token).Result()
	if errors.Is(err, redis.Nil) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}

	var s Session
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return Session{}, false, err
	}

	return s, true, nil
}

func (r *RedisStore) Delete(ctx context.Context, token string) error {
	return r.client.Del(ctx, r.prefix+token).Err()
}
