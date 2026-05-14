package session

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStore_RoundTrip(t *testing.T) {
	store := NewMemoryStore()
	s := Session{AccessToken: "a", ExpiresAt: time.Now().Add(time.Hour), CSRFToken: "csrf", User: UserClaims{Sub: "u"}}

	if err := store.Put(context.Background(), "id-1", s, time.Hour); err != nil {
		t.Fatalf("put: %v", err)
	}

	got, ok, err := store.Get(context.Background(), "id-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !ok {
		t.Fatal("expected session to exist")
	}
	if got.User.Sub != "u" {
		t.Fatalf("unexpected subject: %s", got.User.Sub)
	}

	if err := store.Delete(context.Background(), "id-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, ok, err = store.Get(context.Background(), "id-1")
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if ok {
		t.Fatal("expected session to be deleted")
	}
}

func TestNewStore_UsesRedisWhenConfigured(t *testing.T) {
	store, err := NewStore("redis://127.0.0.1:6379")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, ok := store.(*RedisStore); !ok {
		t.Fatalf("expected RedisStore, got %T", store)
	}
}

func TestNewStore_UsesMemoryWhenRedisMissing(t *testing.T) {
	store, err := NewStore("")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, ok := store.(*MemoryStore); !ok {
		t.Fatalf("expected MemoryStore, got %T", store)
	}
}
