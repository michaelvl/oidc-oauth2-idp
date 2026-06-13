package bff

import (
	"context"
	"errors"

	"golang.org/x/oauth2"
)

type OAuthClient struct {
	Config *oauth2.Config
}

func (c OAuthClient) AuthCodeURL(state, verifier string) string {
	if c.Config == nil {
		return "/login"
	}
	return c.Config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

func (c OAuthClient) ExchangeCode(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	if c.Config == nil {
		return nil, errors.New("oauth config is missing")
	}
	return c.Config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
}

func (c OAuthClient) RefreshTokens(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if c.Config == nil {
		return nil, errors.New("oauth config is missing")
	}
	ts := c.Config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	return ts.Token()
}
