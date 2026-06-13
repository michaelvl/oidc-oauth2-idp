package session

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStore_RoundTrip(t *testing.T) {
	store := NewMemoryStore()
	s := Session{AccessToken: "a", ExpiresAt: time.Now().Add(time.Hour), CSRFToken: "csrf", User: UserClaims{Sub: "u"}}

	token, err := store.Save(context.Background(), s, time.Hour)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	got, ok, err := store.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !ok {
		t.Fatal("expected session to exist")
	}
	if got.User.Sub != "u" {
		t.Fatalf("unexpected subject: %s", got.User.Sub)
	}

	if err := store.Delete(context.Background(), token); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, ok, err = store.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("load after delete: %v", err)
	}
	if ok {
		t.Fatal("expected session to be deleted")
	}
}

func TestNewRedisStore_ParsesURL(t *testing.T) {
	store, err := NewRedisStore("redis://127.0.0.1:6379")
	if err != nil {
		t.Fatalf("new redis store: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}
