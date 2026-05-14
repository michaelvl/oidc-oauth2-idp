package session

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type Store interface {
	Put(ctx context.Context, id string, s Session, ttl time.Duration) error
	Get(ctx context.Context, id string) (Session, bool, error)
	Delete(ctx context.Context, id string) error
}

func NewStore(redisURL string) (Store, error) {
	if redisURL == "" {
		return NewMemoryStore(), nil
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}

	return &RedisStore{
		client: redis.NewClient(opt),
		prefix: "session:",
	}, nil
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

func (m *MemoryStore) Put(_ context.Context, id string, s Session, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[id] = memoryItem{session: s, expires: time.Now().Add(ttl)}
	return nil
}

func (m *MemoryStore) Get(_ context.Context, id string) (Session, bool, error) {
	m.mu.RLock()
	item, ok := m.items[id]
	m.mu.RUnlock()
	if !ok {
		return Session{}, false, nil
	}
	if time.Now().After(item.expires) {
		m.mu.Lock()
		delete(m.items, id)
		m.mu.Unlock()
		return Session{}, false, nil
	}
	return item.session, true, nil
}

func (m *MemoryStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, id)
	return nil
}

type RedisStore struct {
	client *redis.Client
	prefix string
}

func (r *RedisStore) Put(ctx context.Context, id string, s Session, ttl time.Duration) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return r.client.Set(ctx, r.prefix+id, string(b), ttl).Err()
}

func (r *RedisStore) Get(ctx context.Context, id string) (Session, bool, error) {
	raw, err := r.client.Get(ctx, r.prefix+id).Result()
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

func (r *RedisStore) Delete(ctx context.Context, id string) error {
	return r.client.Del(ctx, r.prefix+id).Err()
}
