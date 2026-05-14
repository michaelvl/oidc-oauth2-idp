package session

import "time"

type UserClaims struct {
	Sub     string `json:"sub"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture string `json:"picture"`
}

type Session struct {
	AccessToken  string     `json:"accessToken"`
	RefreshToken string     `json:"refreshToken"`
	IDToken      string     `json:"idToken"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	CSRFToken    string     `json:"csrfToken"`
	User         UserClaims `json:"user"`
}
