package handler

import (
	"sync"
	"time"
)

const oidcStateClaimTTL = 5 * time.Minute

type stateClaims struct {
	mu          sync.Mutex
	claimedAt   map[string]time.Time
	lastCleanup time.Time
	ttl         time.Duration
}

func newStateClaims(ttl time.Duration) *stateClaims {
	return &stateClaims{
		claimedAt: make(map[string]time.Time),
		lastCleanup: time.Now(),
		ttl:       ttl,
	}
}

func (s *stateClaims) Claim(state string) bool {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if now.Sub(s.lastCleanup) >= s.ttl {
		s.cleanupLocked(now)
	}

	if claimedAt, ok := s.claimedAt[state]; ok {
		if now.Sub(claimedAt) < s.ttl {
			return false
		}
	}

	s.claimedAt[state] = now
	return true
}

func (s *stateClaims) cleanupLocked(now time.Time) {
	for state, claimedAt := range s.claimedAt {
		if now.Sub(claimedAt) >= s.ttl {
			delete(s.claimedAt, state)
		}
	}
	s.lastCleanup = now
}
