package session

import (
	"context"
	"encoding/base64"
	"testing"
	"time"
)

const testSecret = "01234567890123456789012345678901"

func testSession() Session {
	return Session{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		IDToken:      "id-token",
		CSRFToken:    "csrf-token",
	}
}

func TestCookieStore_RoundTrip(t *testing.T) {
	store := NewCookieStore(testSecret)
	s := testSession()

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
		t.Fatal("expected session to be found")
	}
	if got.AccessToken != s.AccessToken {
		t.Fatalf("access token mismatch: got %q, want %q", got.AccessToken, s.AccessToken)
	}
	if got.CSRFToken != s.CSRFToken {
		t.Fatalf("csrf token mismatch: got %q, want %q", got.CSRFToken, s.CSRFToken)
	}
}

func TestCookieStore_TamperedToken(t *testing.T) {
	store := NewCookieStore(testSecret)

	token, err := store.Save(context.Background(), testSession(), time.Hour)
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	// Tamper at the raw-byte level so the change is always significant regardless
	// of base64 trailing-bit alignment (flipping the last character is unreliable
	// when n%3!=0 because both 'X' and 'Y' share the same top bits).
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decode saved token: %v", err)
	}
	raw[len(raw)/2] ^= 0xFF
	tampered := base64.RawURLEncoding.EncodeToString(raw)

	_, ok, err := store.Load(context.Background(), tampered)
	if err != nil {
		t.Fatalf("unexpected error on tampered token: %v", err)
	}
	if ok {
		t.Fatal("expected tampered token to yield no session")
	}
}

func TestCookieStore_WrongKey(t *testing.T) {
	store1 := NewCookieStore(testSecret)
	store2 := NewCookieStore("differentSecret_______________________x")

	token, err := store1.Save(context.Background(), testSession(), time.Hour)
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	_, ok, err := store2.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error with wrong key: %v", err)
	}
	if ok {
		t.Fatal("expected wrong key to yield no session")
	}
}

func TestCookieStore_Delete_IsNoOp(t *testing.T) {
	store := NewCookieStore(testSecret)

	token, err := store.Save(context.Background(), testSession(), time.Hour)
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	if err := store.Delete(context.Background(), token); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// token still loads after delete (no server-side state to remove)
	_, ok, err := store.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("load after delete: %v", err)
	}
	if !ok {
		t.Fatal("expected token to still be valid after delete (cookie store has no server-side state)")
	}
}
