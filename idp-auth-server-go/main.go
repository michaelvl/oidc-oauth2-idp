package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const sessionCookieName = "session"

type clientSession struct {
	ClientID            string
	Scope               string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
}

type session struct {
	Subject        string
	SessionID      string
	ClientSessions []clientSession
}

type authContextEntry struct {
	Scope               string
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Subject             string
}

type codeMetadataEntry struct {
	SessionID string
	ClientID  string
	Nonce     string
}

type server struct {
	mu sync.Mutex

	authContext map[string]authContextEntry
	codeMeta    map[string]codeMetadataEntry
	sessions    map[string]session

	templates map[string]*template.Template
	templatesDir string

	appPort     string
	externalURL string
	internalURL string
	apiBaseURL  string

	accessTokenLifetime  int
	refreshTokenLifetime int

	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

type indexData struct {
	Sessions map[string]session
}

type authenticateData struct {
	ReqID string
}

type authorizeData struct {
	ClientID string
	Scope    string
	ReqID    string
}

type endsessionData struct {
	SessionID string
	Subject   string
	RedirURL  string
}

type errorData struct {
	Text string
}

func main() {
	srv, err := newServer()
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.index)
	mux.HandleFunc("/style.css", srv.styleCSS)
	mux.HandleFunc("/logout", srv.logout)
	mux.HandleFunc("/authorize", srv.authorize)
	mux.HandleFunc("/login", srv.login)
	mux.HandleFunc("/approve", srv.approve)
	mux.HandleFunc("/token", srv.token)
	mux.HandleFunc("/userinfo", srv.userinfo)
	mux.HandleFunc("/endsession", srv.endsession)
	mux.HandleFunc("/endsession-approve", srv.endsessionApprove)
	mux.HandleFunc("/.well-known/jwks.json", srv.jwks)
	mux.HandleFunc("/.well-known/openid-configuration", srv.openidConfiguration)

	handler := withCORS(withLogging(mux))

	log.Printf("listening on 0.0.0.0:%s", srv.appPort)
	if err := http.ListenAndServe("0.0.0.0:"+srv.appPort, handler); err != nil {
		log.Fatal(err)
	}
}

func newServer() (*server, error) {
	appPort := getenvDefault("APP_PORT", "5001")
	externalURL := getenvDefault("IDP_EXTERNAL_URL", "http://127.0.0.1:5001")
	internalURL := getenvDefault("IDP_INTERNAL_URL", externalURL)
	apiBaseURL := getenvDefault("API_BASE_URL", "http://127.0.0.1:5002/api")
	accessLifetime := getenvDefaultInt("ACCESS_TOKEN_LIFETIME", 1200)
	refreshLifetime := getenvDefaultInt("REFRESH_TOKEN_LIFETIME", 3600)

	log.Printf("Generate keys")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	templatesDir := getenvDefault("TEMPLATES_DIR", filepath.Join(getenvDefault("KO_DATA_PATH", filepath.Join("idp-auth-server-go", "kodata")), "templates"))
	templates, err := loadTemplates(templatesDir)
	if err != nil {
		return nil, err
	}

	return &server{
		authContext:          map[string]authContextEntry{},
		codeMeta:             map[string]codeMetadataEntry{},
		sessions:             map[string]session{},
		templates:            templates,
		templatesDir:         templatesDir,
		appPort:              appPort,
		externalURL:          externalURL,
		internalURL:          internalURL,
		apiBaseURL:           apiBaseURL,
		accessTokenLifetime:  accessLifetime,
		refreshTokenLifetime: refreshLifetime,
		privateKey:           privateKey,
		publicKey:            &privateKey.PublicKey,
	}, nil
}

func loadTemplates(dir string) (map[string]*template.Template, error) {
	names := []string{"index", "authenticate", "authorize", "endsession", "error"}
	out := make(map[string]*template.Template, len(names))
	for _, name := range names {
		tpl, err := template.ParseFiles(filepath.Join(dir, name+".html"))
		if err != nil {
			return nil, err
		}
		out[name] = tpl
	}
	return out, nil
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	s.mu.Lock()
	data := indexData{Sessions: s.sessions}
	s.mu.Unlock()

	renderTemplate(w, s.templates["index"], data)
}

func (s *server) styleCSS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.templatesDir, "style.css"))
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	sessionID := r.Form.Get("sessionid")
	log.Printf("Logout, session: %s", sessionID)

	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()

	http.Redirect(w, r, s.externalURL, http.StatusSeeOther)
}

func (s *server) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()

	clientID := r.Form.Get("client_id")
	scope := r.Form.Get("scope")
	redirectURI := r.Form.Get("redirect_uri")
	state := r.Form.Get("state")
	nonce := r.Form.Get("nonce")
	prompt := r.Form.Get("prompt")
	codeChallengeMethod := r.Form.Get("code_challenge_method")
	codeChallenge := r.Form.Get("code_challenge")

	reqID := uuid.NewString()
	var sessionCookie string
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		sessionCookie = cookie.Value
	}

	log.Printf("Session cookie: %s", sessionCookie)

	s.mu.Lock()
	if sess, ok := s.sessions[sessionCookie]; ok {
		s.mu.Unlock()
		log.Printf("This is an existing session identified by the session cookie, short-cutting login process...")
		s.issueCodeAndRedirect(w, r, sess, clientID, state, nonce)
		return
	}
	s.mu.Unlock()

	log.Printf("No session cookie")
	if prompt == "none" {
		idTokenHint := r.PostFormValue("id_token_hint")
		idTokenClaims, err := s.decodeJWT(idTokenHint, s.publicKey)
		if err != nil {
			log.Printf("error decoding id_token_hint: %v", err)
			redirURL := buildURL(redirectURI, map[string]string{"error": "login_required", "state": state})
			http.Redirect(w, r, redirURL, http.StatusSeeOther)
			return
		}

		log.Printf("ID token hint claims: %v", idTokenClaims)
		if !audContainsAny(idTokenClaims, []string{s.externalURL, s.internalURL}) {
			log.Printf("ID token hint not for us")
			redirURL := buildURL(redirectURI, map[string]string{"error": "login_required", "state": state})
			http.Redirect(w, r, redirURL, http.StatusSeeOther)
			return
		}

		subject, _ := idTokenClaims["sub"].(string)
		s.mu.Lock()
		existingSessionID := s.getSessionBySubjectLocked(subject)
		if existingSessionID != "" {
			sess := s.sessions[existingSessionID]
			s.mu.Unlock()
			log.Printf("Found existing session %s", existingSessionID)
			s.issueCodeAndRedirect(w, r, sess, clientID, state, nonce)
			return
		}
		s.mu.Unlock()

		log.Printf("No existing session found")
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("error=login_required"))
		return
	}

	s.mu.Lock()
	s.authContext[reqID] = authContextEntry{
		Scope:               scope,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}
	s.mu.Unlock()

	log.Printf("AUTHENTICATE: Requesting login. Scope: '%s', client-id: '%s', state: %s, using request id: %s", scope, clientID, state, reqID)
	renderTemplate(w, s.templates["authenticate"], authenticateData{ReqID: reqID})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	reqID := r.Form.Get("reqid")
	subject := r.Form.Get("username")
	password := r.Form.Get("password")

	if password != "valid" {
		renderTemplate(w, s.templates["error"], errorData{Text: "Authentication error"})
		return
	}

	s.mu.Lock()
	ctx := s.authContext[reqID]
	ctx.Subject = subject
	s.authContext[reqID] = ctx
	s.mu.Unlock()

	log.Printf("LOGIN: Requesting authorization. Scope: '%s', client-id: '%s', state: %s, using request id: %s", ctx.Scope, ctx.ClientID, ctx.State, reqID)
	renderTemplate(w, s.templates["authorize"], authorizeData{ClientID: ctx.ClientID, Scope: ctx.Scope, ReqID: reqID})
}

func (s *server) approve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	reqID := r.Form.Get("reqid")

	s.mu.Lock()
	ctx, ok := s.authContext[reqID]
	s.mu.Unlock()
	if !ok {
		renderTemplate(w, s.templates["error"], errorData{Text: "Unknown request ID"})
		return
	}

	subject := ctx.Subject
	log.Printf("APPROVE: User: '%s', request id: %s", subject, reqID)

	if _, ok := r.Form["approve"]; !ok {
		renderTemplate(w, s.templates["error"], errorData{Text: "Not approved"})
		return
	}

	s.mu.Lock()
	delete(s.authContext, reqID)
	existingSessionID := s.getSessionBySubjectLocked(subject)
	sessionID := existingSessionID
	if sessionID == "" {
		sessionID = uuid.NewString()
	}
	sess := session{
		Subject:   subject,
		SessionID: sessionID,
		ClientSessions: []clientSession{{
			ClientID:            ctx.ClientID,
			Scope:               ctx.Scope,
			RedirectURI:         ctx.RedirectURI,
			CodeChallenge:       ctx.CodeChallenge,
			CodeChallengeMethod: ctx.CodeChallengeMethod,
		}},
	}
	s.sessions[sessionID] = sess
	s.mu.Unlock()

	log.Printf("User: '%s' authorized scope: '%s' for client_id: '%s'", subject, ctx.Scope, ctx.ClientID)
	log.Printf("Created session %s", sessionID)

	s.issueCodeAndRedirect(w, r, sess, ctx.ClientID, ctx.State, ctx.Nonce)
}

func (s *server) issueCodeAndRedirect(w http.ResponseWriter, r *http.Request, sess session, clientID, state, nonce string) {
	code := uuid.NewString()

	s.mu.Lock()
	s.codeMeta[code] = codeMetadataEntry{SessionID: sess.SessionID, ClientID: clientID, Nonce: nonce}
	s.mu.Unlock()

	clientSess := getClientSessionByID(sess, clientID)
	if clientSess == nil {
		renderTemplate(w, s.templates["error"], errorData{Text: "Unknown client session"})
		return
	}

	redirURL := buildURL(clientSess.RedirectURI, map[string]string{"code": code, "state": state})
	log.Printf("Redirecting to callback '%s'", redirURL)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sess.SessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, redirURL, http.StatusSeeOther)
}

func (s *server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	logRequest("GET-TOKEN", r)
	_ = r.ParseForm()

	clientAuth := r.Header.Get("Authorization")
	log.Printf("GET-TOKEN: Client auth: '%s'", clientAuth)

	grantType := r.Form.Get("grant_type")
	log.Printf("GET-TOKEN: Grant type: '%s'", grantType)

	var (
		subject         string
		scope           string
		clientID        string
		sessionID       string
		nonce           string
		accessLifetime  int
		refreshLifetime int
	)

	switch grantType {
	case "authorization_code":
		code := r.Form.Get("code")
		_ = r.Form.Get("redirection_uri")
		codeVerifier := r.Form.Get("code_verifier")

		s.mu.Lock()
		meta, ok := s.codeMeta[code]
		if ok {
			delete(s.codeMeta, code)
		}
		s.mu.Unlock()

		if !ok {
			log.Printf("GET-TOKEN: Invalid code: '%s'", code)
			w.WriteHeader(http.StatusForbidden)
			renderTemplate(w, s.templates["error"], errorData{Text: "Invalid code"})
			return
		}

		log.Printf("GET-TOKEN: Valid code: '%s'", code)
		sessionID = meta.SessionID
		clientID = meta.ClientID
		nonce = meta.Nonce

		s.mu.Lock()
		sess, ok := s.sessions[sessionID]
		s.mu.Unlock()
		if !ok {
			http.Error(w, "error=invalid_grant", http.StatusForbidden)
			return
		}

		subject = sess.Subject
		clientSess := getClientSessionByID(sess, clientID)
		if clientSess == nil {
			http.Error(w, "error=invalid_grant", http.StatusForbidden)
			return
		}

		if clientSess.CodeChallenge != "" {
			log.Printf("GET-TOKEN: Challenge '%s', verifier '%s', method '%s'", clientSess.CodeChallenge, codeVerifier, clientSess.CodeChallengeMethod)
			switch clientSess.CodeChallengeMethod {
			case "plain":
				if codeVerifier != clientSess.CodeChallenge {
					http.Error(w, "error=invalid_grant", http.StatusForbidden)
					return
				}
			case "S256":
				digest := sha256.Sum256([]byte(codeVerifier))
				ourCodeChallenge := base64.RawURLEncoding.EncodeToString(digest[:])
				log.Printf("Self-encoded challenge '%s', got challenge '%s'", ourCodeChallenge, clientSess.CodeChallenge)
				if ourCodeChallenge != clientSess.CodeChallenge {
					http.Error(w, "error=invalid_grant", http.StatusForbidden)
					return
				}
			default:
				http.Error(w, "error=invalid_grant", http.StatusForbidden)
				return
			}
		}

		scope = clientSess.Scope
		accessLifetime = s.accessTokenLifetime
		refreshLifetime = s.refreshTokenLifetime

	case "refresh_token":
		refreshToken := r.Form.Get("refresh_token")
		log.Printf("GET-TOKEN: Refresh token %s", refreshToken)

		refreshClaims, err := s.decodeJWT(refreshToken, s.publicKey)
		if err != nil {
			http.Error(w, "error=invalid_grant", http.StatusUnauthorized)
			return
		}

		sessionID, _ = refreshClaims["session_id"].(string)
		s.mu.Lock()
		_, ok := s.sessions[sessionID]
		s.mu.Unlock()
		if !ok {
			log.Printf("GET-TOKEN: Invalid session, cannot refresh tokens: '%s'", sessionID)
			http.Error(w, "error=invalid_grant", http.StatusUnauthorized)
			return
		}

		subject, _ = refreshClaims["sub"].(string)
		scope, _ = refreshClaims["scope"].(string)
		clientID, _ = refreshClaims["client_id"].(string)
		nonce, _ = refreshClaims["nonce"].(string)
		accessLifetime = intFromAny(refreshClaims["access_token_lifetime"], s.accessTokenLifetime)
		refreshLifetime = intFromAny(refreshClaims["refresh_token_lifetime"], s.refreshTokenLifetime)

	default:
		log.Printf("GET-TOKEN: Invalid grant type: '%s'", grantType)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	log.Printf("GET-TOKEN: Issuing tokens!")
	accessAud := dedupeStrings([]string{s.apiBaseURL, s.externalURL + "/userinfo", s.internalURL + "/userinfo"})
	accessToken, err := s.issueToken(subject, accessAud, map[string]any{
		"token_use": "access",
		"scope":     scope,
	}, time.Now().UTC().Add(time.Duration(accessLifetime)*time.Second))
	if err != nil {
		http.Error(w, "token issue error", http.StatusInternalServerError)
		return
	}

	refreshAud := dedupeStrings([]string{s.externalURL + "/token", s.internalURL + "/token"})
	refreshToken, err := s.issueToken(subject, refreshAud, map[string]any{
		"client_id":              clientID,
		"session_id":             sessionID,
		"access_token_lifetime":  accessLifetime,
		"refresh_token_lifetime": refreshLifetime,
		"nonce":                  nonce,
		"token_use":              "refresh",
		"scope":                  scope,
	}, time.Now().UTC().Add(time.Duration(refreshLifetime)*time.Second))
	if err != nil {
		http.Error(w, "token issue error", http.StatusInternalServerError)
		return
	}

	response := map[string]any{
		"access_token":  accessToken,
		"expires_in":    accessLifetime,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
	}

	if strings.Contains(scope, "openid") {
		claims := map[string]any{}
		if strings.Contains(scope, "profile") {
			claims["name"] = fmt.Sprintf("Name of user %s", capitalize(subject))
			claims["preferred_username"] = capitalize(subject)
			claims["azp"] = clientID
			if nonce != "" {
				claims["nonce"] = nonce
			}
		}

		idToken, err := s.issueToken(subject, []string{clientID, s.externalURL}, claims, time.Now().UTC().Add(60*time.Minute))
		if err != nil {
			http.Error(w, "token issue error", http.StatusInternalServerError)
			return
		}
		response["id_token"] = idToken
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *server) userinfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	logRequest("GET-USERINFO", r)

	auth := r.Header.Get("Authorization")
	log.Printf("GET-USERINFO: Access token: '%s'", auth)

	parts := strings.Fields(auth)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		renderTemplate(w, s.templates["error"], errorData{Text: "Invalid authorization"})
		return
	}

	claims, err := s.decodeJWT(parts[1], s.publicKey)
	if err != nil {
		renderTemplate(w, s.templates["error"], errorData{Text: "Invalid authorization"})
		return
	}

	scope, _ := claims["scope"].(string)
	log.Printf("GET-USERINFO: Access token audience: '%v'", claims["aud"])
	log.Printf("GET-USERINFO: Scope '%s'", scope)

	out := map[string]any{}
	if strings.Contains(scope, "profile") {
		sub, _ := claims["sub"].(string)
		out["name"] = fmt.Sprintf("Name of user is %s", capitalize(sub))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *server) endsession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()

	idTokenHint := r.Form.Get("id_token_hint")
	redirURL := r.Form.Get("post_logout_redirect_uri")

	claims, err := s.decodeJWT(idTokenHint, s.publicKey)
	if err != nil {
		renderTemplate(w, s.templates["error"], errorData{Text: "ID token not for us"})
		return
	}

	if !audContainsAny(claims, []string{s.externalURL, s.internalURL}) {
		log.Printf("END-SESSION: ID token hint not for us")
		renderTemplate(w, s.templates["error"], errorData{Text: "ID token not for us"})
		return
	}

	log.Printf("END-SESSION: ID token hint claims: %v", claims)
	sub, _ := claims["sub"].(string)

	s.mu.Lock()
	existingSessionID := s.getSessionBySubjectLocked(sub)
	if existingSessionID != "" {
		sess := s.sessions[existingSessionID]
		s.mu.Unlock()
		renderTemplate(w, s.templates["endsession"], endsessionData{SessionID: existingSessionID, Subject: sess.Subject, RedirURL: redirURL})
		return
	}
	s.mu.Unlock()

	renderTemplate(w, s.templates["error"], errorData{Text: "Error logging out"})
}

func (s *server) endsessionApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	sessionID := r.Form.Get("sessionid")
	redirURL := r.Form.Get("redirurl")

	log.Printf("END-SESSION-APPROVE: Ending session: %s", sessionID)
	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()

	http.Redirect(w, r, redirURL, http.StatusSeeOther)
}

func (s *server) jwks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	n := base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.publicKey.E)).Bytes())

	jwks := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": "k0",
			"alg": "RS256",
			"use": "sig",
			"n":   n,
			"e":   e,
		}},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}

func (s *server) openidConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	config := map[string]any{
		"issuer":                 s.externalURL,
		"authorization_endpoint": s.externalURL + "/authorize",
		"token_endpoint":         s.externalURL + "/token",
		"userinfo_endpoint":      s.externalURL + "/userinfo",
		"jwks_uri":               s.externalURL + "/.well-known/jwks.json",
		"end_session_endpoint":   s.externalURL + "/endsession",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(config)
}

func (s *server) issueToken(subject string, audience []string, claims map[string]any, expiry time.Time) (string, error) {
	allClaims := jwt.MapClaims{}
	for k, v := range claims {
		allClaims[k] = v
	}
	allClaims["sub"] = subject
	allClaims["iss"] = s.externalURL
	allClaims["aud"] = audience
	allClaims["iat"] = time.Now().UTC().Unix()
	allClaims["exp"] = expiry.UTC().Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, allClaims)
	token.Header["kid"] = "k0"

	return token.SignedString(s.privateKey)
}

func (s *server) decodeJWT(token string, key *rsa.PublicKey) (map[string]any, error) {
	tok, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	out := map[string]any{}
	for k, v := range claims {
		out[k] = v
	}
	return out, nil
}

func buildURL(base string, params map[string]string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *server) getSessionBySubjectLocked(sub string) string {
	for sessionID, sess := range s.sessions {
		if sess.Subject == sub {
			return sessionID
		}
	}
	return ""
}

func getClientSessionByID(sess session, clientID string) *clientSession {
	for i := range sess.ClientSessions {
		if sess.ClientSessions[i].ClientID == clientID {
			return &sess.ClientSessions[i]
		}
	}
	return nil
}

func renderTemplate(w http.ResponseWriter, tpl *template.Template, data any) {
	if err := tpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func logRequest(prefix string, req *http.Request) {
	body, _ := readBody(req)
	log.Printf("%s # %s %s", prefix, req.Method, req.URL.Path)
	for name, values := range req.Header {
		for _, value := range values {
			log.Printf("%s # %s: %s", prefix, name, value)
		}
	}
	log.Printf("%s #", prefix)
	for _, line := range strings.Split(body, "\n") {
		log.Printf("%s # %s", prefix, line)
	}
}

func readBody(req *http.Request) (string, error) {
	if req.Body == nil {
		return "", nil
	}
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	return string(bodyBytes), nil
}

func audContains(claims map[string]any, want string) bool {
	aud, ok := claims["aud"]
	if !ok {
		return false
	}
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func audContainsAny(claims map[string]any, wants []string) bool {
	for _, want := range wants {
		if audContains(claims, want) {
			return true
		}
	}
	return false
}

func dedupeStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func intFromAny(v any, def int) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	default:
		return def
	}
}

func getenvDefault(name, def string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	return v
}

func getenvDefaultInt(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}
