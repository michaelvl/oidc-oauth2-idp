package session

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type UserClaims struct {
	Sub     string `json:"sub"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture string `json:"picture"`
}

type Session struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	IDToken      string    `json:"idToken"`
	CSRFToken    string    `json:"csrfToken"`
}

func ParseIDTokenClaims(rawIDToken string) (UserClaims, error) {
	parts := strings.SplitN(rawIDToken, ".", 3)
	if len(parts) != 3 {
		return UserClaims{}, fmt.Errorf("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return UserClaims{}, err
	}
	var claims UserClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return UserClaims{}, err
	}
	return claims, nil
}
