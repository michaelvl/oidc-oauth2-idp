package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const sessionCookieName = "session"

type clientSession struct {
	SessionID           string // per-RP login ID; used as csid claim in tokens
	ClientID            string
	AdvertisedSub       string // the sub value sent to this RP (public: internal Sub; pairwise: HMAC of Sub)
	Scope               string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	IDTokenClaims       map[string]any
	AccessTokenClaims   map[string]any
	RefreshTokenClaims  map[string]any
}

type session struct {
	Username       string // the username entered at login; used for profile claims only
	Sub            string // the real/internal subject identifier; basis for AdvertisedSub
	CookieID       string // IdP browser-session cookie value; map key for s.sessions
	ClientSessions []clientSession
}

type authContextEntry struct {
	// FIXME: Add a timestamp field so stale auth requests can be rejected in /approve.
	Scope               string
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Username            string
	Sub                 string
}

type codeMetadataEntry struct {
	CookieID string // parent session CookieID; used to look up the session at token exchange
	ClientID string
	Nonce    string
}

// registrationMethodAutomatic marks a client that was registered implicitly the
// first time it was seen at /authorize, i.e. without the client ever asking to
// be registered, as opposed to registrationMethodDynamic.
const registrationMethodAutomatic = "automatic"

// registrationMethodDynamic marks a client that registered itself at /register
// using RFC 7591 dynamic client registration.
const registrationMethodDynamic = "dynamic"

// clientRegistration holds the RFC 7591 client metadata for a registered client.
// Field names and JSON tags follow RFC 7591 section 2 so a registration can be
// served verbatim as a client registration document, with the non-standard
// registration_method recording how the client came to be registered.
type clientRegistration struct {
	ClientID         string `json:"client_id"`
	ClientIDIssuedAt int64  `json:"client_id_issued_at"`

	// ClientSecret is issued only to clients that register dynamically with a
	// secret-based token endpoint auth method. ClientSecretExpiresAt is a pointer
	// because RFC 7591 requires it alongside a secret, where 0 means "never
	// expires" - a value omitempty would drop.
	ClientSecret          string `json:"client_secret,omitempty"`
	ClientSecretExpiresAt *int64 `json:"client_secret_expires_at,omitempty"`

	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`

	// Descriptive metadata. Automatic registration has no source for these; they
	// are here for clients that register themselves with RFC 7591 metadata.
	ClientName      string   `json:"client_name,omitempty"`
	ClientURI       string   `json:"client_uri,omitempty"`
	LogoURI         string   `json:"logo_uri,omitempty"`
	Contacts        []string `json:"contacts,omitempty"`
	TosURI          string   `json:"tos_uri,omitempty"`
	PolicyURI       string   `json:"policy_uri,omitempty"`
	JwksURI         string   `json:"jwks_uri,omitempty"`
	SoftwareID      string   `json:"software_id,omitempty"`
	SoftwareVersion string   `json:"software_version,omitempty"`

	// RegistrationMethod is an extension to RFC 7591 metadata: it records how
	// this registration came about, e.g. "automatic".
	RegistrationMethod string `json:"registration_method"`
}

type server struct {
	mu sync.Mutex

	logger *slog.Logger

	authContext map[string]authContextEntry
	codeMeta    map[string]codeMetadataEntry
	sessions    map[string]session
	clients     map[string]clientRegistration

	templates    map[string]*template.Template
	templatesDir string

	appPort           string
	externalURL       string
	protectPictureURL bool
	extraAudiences    []string
	emailDomain       string

	accessTokenLifetime  int
	refreshTokenLifetime int

	subjectType  string // "public" or "pairwise"
	pairwiseSalt []byte // HMAC-SHA256 key; only set when subjectType == "pairwise"

	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

type indexData struct {
	Sessions []sessionView
}

type sessionView struct {
	CookieID       string
	Username       string
	Sub            string
	AvatarURL      string
	ClientSessions []clientSessionView
}

type clientSessionView struct {
	ClientID              string
	AdvertisedSub         string
	Scope                 string
	IDTokenIssued         bool
	RefreshTokenIssued    bool
	IDTokenClaimsJSON     string
	AccessTokenClaimsJSON string
	IDTokenExpiry         string
	AccessTokenExpiry     string
	RefreshTokenExpiry    string
}

type clientsData struct {
	Clients []clientRegistrationView
}

// clientRegistrationView is deliberately thin: the metadata document carries
// every registered field, so the page only lifts out how and when the client was
// registered, which are not obvious from a JSON blob.
type clientRegistrationView struct {
	ClientID           string
	RegistrationMethod string
	IssuedAt           string
	MetadataJSON       string
}

type authenticateData struct {
	ReqID string
}

type authorizeData struct {
	ClientID              string
	Scope                 string
	ReqID                 string
	IDTokenClaimsJSON     string
	AccessTokenClaimsJSON string
	ErrorText             string
	AvatarURL             string
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
	logLevel, err := parseLogLevelFlag()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	srv, err := newServer(logger)
	if err != nil {
		logger.Error("startup failed", "error", err.Error())
		os.Exit(1)
	}

	handler := withCORS(withLogging(logger, newMux(srv)))

	logger.Info("listening", "addr", "0.0.0.0:"+srv.appPort)
	if err := http.ListenAndServe("0.0.0.0:"+srv.appPort, handler); err != nil {
		logger.Error("server exited", "error", err.Error())
		os.Exit(1)
	}
}

func newMux(srv *server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.index)
	mux.HandleFunc("/clients", srv.clientsPage)
	mux.HandleFunc("/register", srv.register)
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
	for i := 1; i <= 8; i++ {
		mux.HandleFunc(fmt.Sprintf("/avatars/%d.svg", i), srv.avatar)
		mux.HandleFunc(fmt.Sprintf("/internal/avatars/%d.svg", i), srv.internalAvatar)
	}
	return mux
}

func parseLogLevelFlag() (slog.Level, error) {
	logLevelFlag := flag.String("log-level", "info", "log level: debug|info|warn|error")
	flag.Parse()

	switch strings.ToLower(strings.TrimSpace(*logLevelFlag)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid --log-level %q (expected: debug, info, warn, error)", *logLevelFlag)
	}
}

func newServer(logger *slog.Logger) (*server, error) {
	appPort := getenvDefault("PORT", "5001")
	externalURL := getenvDefault("IDP_EXTERNAL_URL", "http://127.0.0.1:5001")
	protectPictureURL := getenvDefaultBool("PROTECT_PICTURE_URL", false)
	extraAudiences := getenvCSV("EXTRA_AUDIENCES")
	emailDomain := getenvDefault("EMAIL_DOMAIN", "example.com")
	accessLifetime := getenvDefaultInt("ACCESS_TOKEN_LIFETIME", 1200)
	refreshLifetime := getenvDefaultInt("REFRESH_TOKEN_LIFETIME", 3600)

	subjectType := getenvDefault("SUBJECT_TYPE", "public")
	var pairwiseSalt []byte
	if subjectType == "pairwise" {
		saltHex := getenvDefault("PAIRWISE_SALT", "")
		if saltHex == "" {
			return nil, fmt.Errorf("PAIRWISE_SALT is required when SUBJECT_TYPE=pairwise")
		}
		var err error
		pairwiseSalt, err = hex.DecodeString(saltHex)
		if err != nil {
			return nil, fmt.Errorf("invalid PAIRWISE_SALT (expected hex): %w", err)
		}
		if len(pairwiseSalt) < 16 {
			return nil, fmt.Errorf("PAIRWISE_SALT must be at least 16 bytes (32 hex chars)")
		}
	} else if subjectType != "public" {
		return nil, fmt.Errorf("invalid SUBJECT_TYPE %q (expected: public, pairwise)", subjectType)
	}

	logger.Info("generating keys")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	templatesDir := getenvDefault("TEMPLATES_DIR", filepath.Join(getenvDefault("KO_DATA_PATH", filepath.Join("idp-auth-server", "kodata")), "templates"))
	templates, err := loadTemplates(templatesDir)
	if err != nil {
		return nil, err
	}

	return &server{
		logger:               logger,
		authContext:          map[string]authContextEntry{},
		codeMeta:             map[string]codeMetadataEntry{},
		sessions:             map[string]session{},
		clients:              map[string]clientRegistration{},
		templates:            templates,
		templatesDir:         templatesDir,
		appPort:              appPort,
		externalURL:          externalURL,
		protectPictureURL:    protectPictureURL,
		extraAudiences:       extraAudiences,
		emailDomain:          emailDomain,
		accessTokenLifetime:  accessLifetime,
		refreshTokenLifetime: refreshLifetime,
		subjectType:          subjectType,
		pairwiseSalt:         pairwiseSalt,
		privateKey:           privateKey,
		publicKey:            &privateKey.PublicKey,
	}, nil
}

func loadTemplates(dir string) (map[string]*template.Template, error) {
	names := []string{"index", "clients", "authenticate", "authorize", "endsession", "error"}
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

func withLogging(logger *slog.Logger, next http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	s.mu.Lock()
	views := make([]sessionView, 0, len(s.sessions))
	for cookieID, sess := range s.sessions {
		clientViews := make([]clientSessionView, 0, len(sess.ClientSessions))
		for _, clientSess := range sess.ClientSessions {
			idTokenClaimsJSON, err := claimsToPrettyJSON(clientSess.IDTokenClaims)
			if err != nil {
				idTokenClaimsJSON = "{}"
			}
			accessTokenClaimsJSON, err := claimsToPrettyJSON(clientSess.AccessTokenClaims)
			if err != nil {
				accessTokenClaimsJSON = "{}"
			}
			idTokenExpiry := formatExpiryClaim(clientSess.IDTokenClaims)
			accessTokenExpiry := formatExpiryClaim(clientSess.AccessTokenClaims)
			refreshTokenExpiry := formatExpiryClaim(clientSess.RefreshTokenClaims)
			clientViews = append(clientViews, clientSessionView{
				ClientID:              clientSess.ClientID,
				AdvertisedSub:         clientSess.AdvertisedSub,
				Scope:                 clientSess.Scope,
				IDTokenIssued:         clientSess.IDTokenClaims != nil,
				RefreshTokenIssued:    clientSess.RefreshTokenClaims != nil,
				IDTokenClaimsJSON:     idTokenClaimsJSON,
				AccessTokenClaimsJSON: accessTokenClaimsJSON,
				IDTokenExpiry:         idTokenExpiry,
				AccessTokenExpiry:     accessTokenExpiry,
				RefreshTokenExpiry:    refreshTokenExpiry,
			})
		}
		views = append(views, sessionView{
			CookieID:       cookieID,
			Username:       sess.Username,
			Sub:            sess.Sub,
			AvatarURL:      s.internalAvatarURL(sess.Username),
			ClientSessions: clientViews,
		})
	}
	data := indexData{Sessions: views}
	s.mu.Unlock()

	renderTemplate(w, s.templates["index"], data)
}

func (s *server) clientsPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	s.mu.Lock()
	regs := make([]clientRegistration, 0, len(s.clients))
	for _, reg := range s.clients {
		regs = append(regs, reg)
	}
	s.mu.Unlock()

	// Oldest registration first, with the client ID breaking ties so the listing
	// is stable across reloads.
	sort.Slice(regs, func(i, j int) bool {
		if regs[i].ClientIDIssuedAt != regs[j].ClientIDIssuedAt {
			return regs[i].ClientIDIssuedAt < regs[j].ClientIDIssuedAt
		}
		return regs[i].ClientID < regs[j].ClientID
	})

	views := make([]clientRegistrationView, 0, len(regs))
	for _, reg := range regs {
		metadataJSON, err := clientMetadataJSON(reg)
		if err != nil {
			metadataJSON = "{}"
		}
		views = append(views, clientRegistrationView{
			ClientID:           reg.ClientID,
			RegistrationMethod: reg.RegistrationMethod,
			IssuedAt:           time.Unix(reg.ClientIDIssuedAt, 0).UTC().Format(time.RFC3339),
			MetadataJSON:       metadataJSON,
		})
	}

	renderTemplate(w, s.templates["clients"], clientsData{Clients: views})
}

// Metadata values this IdP accepts at the dynamic registration endpoint. The
// token endpoint enforces these auth methods for dynamically registered clients
// only; automatically registered clients are never authenticated.
var (
	supportedGrantTypes               = []string{"authorization_code", "refresh_token"}
	supportedResponseTypes            = []string{"code"}
	supportedTokenEndpointAuthMethods = []string{"client_secret_basic", "client_secret_post", "none"}
)

// register implements RFC 7591 dynamic client registration. The endpoint is open:
// no initial access token is required, matching the rest of this IdP's permissive
// demo posture.
func (s *server) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	logRequest(s.log(), "register", r)

	// Decoding straight into clientRegistration reuses the RFC 7591 JSON tags;
	// every server-controlled field is overwritten below, so a client cannot
	// choose its own client_id, secret, or registration method.
	var reg clientRegistration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		writeRegistrationError(w, "invalid_client_metadata", "request body must be a JSON object of client metadata")
		return
	}

	if err := normalizeRegistration(&reg); err != nil {
		writeRegistrationError(w, err.code, err.description)
		return
	}

	reg.ClientID = uuid.NewString()
	reg.ClientIDIssuedAt = time.Now().UTC().Unix()
	reg.RegistrationMethod = registrationMethodDynamic

	if reg.TokenEndpointAuthMethod != "none" {
		secret, err := newClientSecret()
		if err != nil {
			s.log().Error("client secret generation failed", "error", err.Error())
			writeRegistrationError(w, "invalid_client_metadata", "could not issue a client secret")
			return
		}
		reg.ClientSecret = secret
		// 0 means the secret does not expire (RFC 7591 section 3.2.1).
		neverExpires := int64(0)
		reg.ClientSecretExpiresAt = &neverExpires
	}

	s.mu.Lock()
	if s.clients == nil {
		s.clients = map[string]clientRegistration{}
	}
	s.clients[reg.ClientID] = reg
	s.mu.Unlock()

	s.log().Info("registered client", "client_id", reg.ClientID, "registration_method", reg.RegistrationMethod, "client_name", reg.ClientName)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(reg)
}

// registrationError is an RFC 7591 section 3.2.2 registration error response.
type registrationError struct {
	code        string
	description string
}

// normalizeRegistration applies RFC 7591 defaults to client-supplied metadata and
// rejects anything this IdP cannot honour.
func normalizeRegistration(reg *clientRegistration) *registrationError {
	if len(reg.GrantTypes) == 0 {
		reg.GrantTypes = []string{"authorization_code"}
	}
	if len(reg.ResponseTypes) == 0 {
		reg.ResponseTypes = []string{"code"}
	}
	if reg.TokenEndpointAuthMethod == "" {
		reg.TokenEndpointAuthMethod = "client_secret_basic"
	}

	for _, grant := range reg.GrantTypes {
		if !slices.Contains(supportedGrantTypes, grant) {
			return &registrationError{"invalid_client_metadata", fmt.Sprintf("unsupported grant_type %q", grant)}
		}
	}
	for _, responseType := range reg.ResponseTypes {
		if !slices.Contains(supportedResponseTypes, responseType) {
			return &registrationError{"invalid_client_metadata", fmt.Sprintf("unsupported response_type %q", responseType)}
		}
	}
	if !slices.Contains(supportedTokenEndpointAuthMethods, reg.TokenEndpointAuthMethod) {
		return &registrationError{"invalid_client_metadata", fmt.Sprintf("unsupported token_endpoint_auth_method %q", reg.TokenEndpointAuthMethod)}
	}

	// The authorization_code grant is the only redirect-based flow here, so a
	// client asking for it must say where to redirect.
	if slices.Contains(reg.GrantTypes, "authorization_code") && len(reg.RedirectURIs) == 0 {
		return &registrationError{"invalid_redirect_uri", "redirect_uris is required for the authorization_code grant"}
	}
	for _, redirectURI := range reg.RedirectURIs {
		if err := validateRedirectURI(redirectURI); err != nil {
			return &registrationError{"invalid_redirect_uri", err.Error()}
		}
	}

	reg.RedirectURIs = dedupeStrings(reg.RedirectURIs)
	reg.Scope = strings.Join(dedupeStrings(strings.Fields(reg.Scope)), " ")
	reg.GrantTypes = dedupeStrings(reg.GrantTypes)
	reg.ResponseTypes = dedupeStrings(reg.ResponseTypes)
	return nil
}

// validateRedirectURI enforces RFC 7591 section 2: a redirect URI must be an
// absolute URI and must not carry a fragment.
func validateRedirectURI(redirectURI string) error {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("redirect_uri %q is not a valid URI", redirectURI)
	}
	if !u.IsAbs() {
		return fmt.Errorf("redirect_uri %q must be an absolute URI", redirectURI)
	}
	if u.Fragment != "" || strings.Contains(redirectURI, "#") {
		return fmt.Errorf("redirect_uri %q must not contain a fragment", redirectURI)
	}
	return nil
}

func newClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func writeRegistrationError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// registerClientLocked registers a client the first time it is seen and keeps the
// observed metadata current on later requests. This IdP accepts any client, so
// registration is a recording of what the client did, not a decision to admit it.
// Callers must hold s.mu.
func (s *server) registerClientLocked(clientID, redirectURI, scope string) {
	if clientID == "" {
		return
	}
	if s.clients == nil {
		s.clients = map[string]clientRegistration{}
	}

	reg, known := s.clients[clientID]
	if known && reg.RegistrationMethod != registrationMethodAutomatic {
		// A client that registered itself owns its metadata; what it happens to
		// send on the wire must not silently widen its registration.
		return
	}
	if !known {
		reg = clientRegistration{
			ClientID:         clientID,
			ClientIDIssuedAt: time.Now().UTC().Unix(),
			ResponseTypes:    []string{"code"},
			GrantTypes:       []string{"authorization_code"},
			// Automatic registration never sees the client register, so there is no
			// secret to compare and no way to learn how it authenticates. Recording
			// "none" keeps the registration honest about what is actually enforced.
			// FIXME: Authenticate automatically registered clients - doing so needs a
			// way to provision a secret out of band, or an initial access token on
			// /register so every client arrives through dynamic registration.
			TokenEndpointAuthMethod: "none",
			RegistrationMethod:      registrationMethodAutomatic,
		}
	}

	if redirectURI != "" {
		reg.RedirectURIs = dedupeStrings(append(reg.RedirectURIs, redirectURI))
	}
	if scope != "" {
		reg.Scope = strings.Join(dedupeStrings(append(strings.Fields(reg.Scope), strings.Fields(scope)...)), " ")
	}
	if hasScope(scope, "offline_access") {
		reg.GrantTypes = dedupeStrings(append(reg.GrantTypes, "refresh_token"))
	}

	s.clients[clientID] = reg

	if !known {
		s.log().Info("registered client", "client_id", clientID, "registration_method", reg.RegistrationMethod, "redirect_uri", redirectURI, "scope", scope)
	}
}

// clientMetadataJSON renders a registration as the RFC 7591 client metadata
// document that /clients displays.
func clientMetadataJSON(reg clientRegistration) (string, error) {
	b, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *server) styleCSS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.templatesDir, "style.css"))
}

func (s *server) avatar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	if s.protectPictureURL {
		claims, err := s.extractAccessToken(r)
		if err != nil {
			s.writeBearerError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		csid, _ := claims["csid"].(string)
		s.mu.Lock()
		_, sess, cs := s.getSessionByClientSessionIDLocked(csid)
		s.mu.Unlock()
		if cs == nil {
			s.writeBearerError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		if filepath.Base(r.URL.Path) != fmt.Sprintf("%d.svg", avatarIndex(sess.Username)) {
			s.writeBearerError(w, http.StatusForbidden, "invalid_token")
			return
		}
	}

	// Extract filename from path (e.g. /avatars/3.svg -> 3.svg)
	name := filepath.Base(r.URL.Path)
	w.Header().Set("Content-Type", "image/svg+xml")
	http.ServeFile(w, r, filepath.Join(s.templatesDir, "avatars", name))
}

func (s *server) internalAvatar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	name := filepath.Base(r.URL.Path)
	w.Header().Set("Content-Type", "image/svg+xml")
	http.ServeFile(w, r, filepath.Join(s.templatesDir, "avatars", name))
}

// avatarIndex returns a stable 1-based index (1–8) derived from the username.
func avatarIndex(username string) int {
	var sum int
	for _, b := range []byte(username) {
		sum += int(b)
	}
	return (sum % 8) + 1
}

func (s *server) internalAvatarURL(username string) string {
	return fmt.Sprintf("%s/internal/avatars/%d.svg", s.externalURL, avatarIndex(username))
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	cookieID := r.Form.Get("cookieid")
	s.log().Info("logout", "cookie_id", cookieID)

	s.mu.Lock()
	delete(s.sessions, cookieID)
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
	// FIXME: Validate client_id and redirect_uri against a registered client registry.
	state := r.Form.Get("state")
	nonce := r.Form.Get("nonce")
	prompt := r.Form.Get("prompt")
	codeChallengeMethod := r.Form.Get("code_challenge_method")
	codeChallenge := r.Form.Get("code_challenge")

	s.mu.Lock()
	s.registerClientLocked(clientID, redirectURI, scope)
	s.mu.Unlock()

	reqID := uuid.NewString()
	var sessionCookie string
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		sessionCookie = cookie.Value
	}

	s.log().Debug("authorize session cookie", "session_cookie", sessionCookie)

	s.mu.Lock()
	if sess, ok := s.sessions[sessionCookie]; ok {
		sess = updateClientSessionPKCE(sess, clientID, codeChallenge, codeChallengeMethod)
		if existing := getClientSessionByID(sess, clientID); existing != nil && existing.RedirectURI != redirectURI {
			s.log().Warn("redirectURI mismatch for existing session, updating to incoming value",
				"stored", existing.RedirectURI, "incoming", redirectURI, "client_id", clientID)
		}
		sess = updateClientSessionRedirectURI(sess, clientID, redirectURI)
		s.sessions[sessionCookie] = sess
		s.mu.Unlock()
		s.log().Info("authorize with existing session cookie", "session_id", sessionCookie)
		s.issueCodeAndRedirect(w, r, sess, clientID, state, nonce)
		return
	}
	s.mu.Unlock()

	s.log().Debug("authorize without session cookie")
	if prompt == "none" {
		// r.Form covers both the query string and the POST body; silent-auth
		// requests from a hidden iframe are GETs carrying the hint as a query
		// parameter.
		idTokenHint := r.Form.Get("id_token_hint")
		idTokenClaims, err := s.decodeJWT(idTokenHint, s.publicKey)
		if err != nil {
			s.log().Warn("failed to decode id_token_hint", "error", err.Error())
			redirURL := buildURL(redirectURI, map[string]string{"error": "login_required", "state": state, "iss": s.externalURL})
			http.Redirect(w, r, redirURL, http.StatusSeeOther)
			return
		}

		s.log().Debug("id_token_hint claims", "claims", idTokenClaims)

		advertisedSub, _ := idTokenClaims["sub"].(string)
		s.mu.Lock()
		existingSessionID := s.getSessionByAdvertisedSubLocked(advertisedSub)
		if existingSessionID != "" {
			sess := s.sessions[existingSessionID]
			sess = updateClientSessionPKCE(sess, clientID, codeChallenge, codeChallengeMethod)
			if existing := getClientSessionByID(sess, clientID); existing != nil && existing.RedirectURI != redirectURI {
				s.log().Warn("redirectURI mismatch for existing session, updating to incoming value",
					"stored", existing.RedirectURI, "incoming", redirectURI, "client_id", clientID)
			}
			sess = updateClientSessionRedirectURI(sess, clientID, redirectURI)
			s.sessions[existingSessionID] = sess
			s.mu.Unlock()
			s.log().Info("found existing session by subject", "session_id", existingSessionID)
			s.issueCodeAndRedirect(w, r, sess, clientID, state, nonce)
			return
		}
		s.mu.Unlock()

		s.log().Info("no existing session found for subject")
		redirURL := buildURL(redirectURI, map[string]string{"error": "login_required", "state": state, "iss": s.externalURL})
		http.Redirect(w, r, redirURL, http.StatusSeeOther)
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

	s.log().Info("requesting login", "scope", scope, "client_id", clientID, "state", state, "request_id", reqID)
	renderTemplate(w, s.templates["authenticate"], authenticateData{ReqID: reqID})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	reqID := r.Form.Get("reqid")
	username := r.Form.Get("username")
	sub := "internal|" + username // internal subject: stable, distinct from username
	password := r.Form.Get("password")

	if password != "valid" {
		renderTemplate(w, s.templates["error"], errorData{Text: "Authentication error"})
		return
	}

	s.mu.Lock()
	ctx := s.authContext[reqID]
	ctx.Username = username
	ctx.Sub = sub
	s.authContext[reqID] = ctx
	s.mu.Unlock()

	idTokenClaimsJSON, err := claimsToPrettyJSON(s.defaultIDTokenClaims(ctx))
	if err != nil {
		http.Error(w, "claims serialization error", http.StatusInternalServerError)
		return
	}
	accessTokenClaimsJSON, err := claimsToPrettyJSON(s.defaultAccessTokenClaims(ctx))
	if err != nil {
		http.Error(w, "claims serialization error", http.StatusInternalServerError)
		return
	}

	s.log().Info("requesting authorization", "scope", ctx.Scope, "client_id", ctx.ClientID, "state", ctx.State, "request_id", reqID)
	renderTemplate(w, s.templates["authorize"], authorizeData{
		ClientID:              ctx.ClientID,
		Scope:                 ctx.Scope,
		ReqID:                 reqID,
		IDTokenClaimsJSON:     idTokenClaimsJSON,
		AccessTokenClaimsJSON: accessTokenClaimsJSON,
		AvatarURL:             s.internalAvatarURL(username),
	})
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

	username := ctx.Username
	sub := ctx.Sub
	s.log().Info("approve request", "username", username, "request_id", reqID)

	if _, ok := r.Form["approve"]; !ok {
		renderTemplate(w, s.templates["error"], errorData{Text: "Not approved"})
		return
	}
	// FIXME: Validate request age and reject stale auth requests.

	idTokenClaimsJSON := r.Form.Get("id_token_claims_json")
	accessTokenClaimsJSON := r.Form.Get("access_token_claims_json")
	// FIXME: Validate that the requested scope is permitted for this client_id.
	idTokenClaims, err := parseClaimsJSON(idTokenClaimsJSON)
	if err != nil {
		renderTemplate(w, s.templates["authorize"], authorizeData{
			ClientID:              ctx.ClientID,
			Scope:                 ctx.Scope,
			ReqID:                 reqID,
			IDTokenClaimsJSON:     idTokenClaimsJSON,
			AccessTokenClaimsJSON: accessTokenClaimsJSON,
			ErrorText:             "ID token claims must be valid JSON object",
			AvatarURL:             s.internalAvatarURL(username),
		})
		return
	}
	accessTokenClaims, err := parseClaimsJSON(accessTokenClaimsJSON)
	if err != nil {
		renderTemplate(w, s.templates["authorize"], authorizeData{
			ClientID:              ctx.ClientID,
			Scope:                 ctx.Scope,
			ReqID:                 reqID,
			IDTokenClaimsJSON:     idTokenClaimsJSON,
			AccessTokenClaimsJSON: accessTokenClaimsJSON,
			ErrorText:             "Access token claims must be valid JSON object",
			AvatarURL:             s.internalAvatarURL(username),
		})
		return
	}

	s.mu.Lock()
	delete(s.authContext, reqID)
	sess, found := s.getSessionBySubLocked(sub)
	if !found {
		sess = session{Username: username, Sub: sub, CookieID: uuid.NewString()}
	}
	csSessionID := ""
	for _, cs := range sess.ClientSessions {
		if cs.ClientID == ctx.ClientID {
			csSessionID = cs.SessionID
			break
		}
	}
	if csSessionID == "" {
		csSessionID = uuid.NewString()
	}
	sess.ClientSessions = upsertClientSession(sess.ClientSessions, clientSession{
		SessionID:           csSessionID,
		ClientID:            ctx.ClientID,
		AdvertisedSub:       s.computeAdvertisedSub(sub, sectorIdentifier(ctx.RedirectURI, ctx.ClientID)),
		Scope:               ctx.Scope,
		RedirectURI:         ctx.RedirectURI,
		CodeChallenge:       ctx.CodeChallenge,
		CodeChallengeMethod: ctx.CodeChallengeMethod,
		IDTokenClaims:       idTokenClaims,
		AccessTokenClaims:   accessTokenClaims,
	})
	s.sessions[sess.CookieID] = sess
	s.mu.Unlock()

	s.log().Info("user authorized", "username", username, "scope", ctx.Scope, "client_id", ctx.ClientID)
	s.log().Info("created session", "cookie_id", sess.CookieID, "client_session_id", csSessionID)

	s.issueCodeAndRedirect(w, r, sess, ctx.ClientID, ctx.State, ctx.Nonce)
}

func (s *server) issueCodeAndRedirect(w http.ResponseWriter, r *http.Request, sess session, clientID, state, nonce string) {
	code := uuid.NewString()

	s.mu.Lock()
	s.codeMeta[code] = codeMetadataEntry{CookieID: sess.CookieID, ClientID: clientID, Nonce: nonce}
	s.mu.Unlock()

	clientSess := getClientSessionByID(sess, clientID)
	if clientSess == nil {
		renderTemplate(w, s.templates["error"], errorData{Text: "Unknown client session"})
		return
	}

	// RFC 9207: the issuer identifier lets clients detect mix-up attacks.
	redirURL := buildURL(clientSess.RedirectURI, map[string]string{"code": code, "state": state, "iss": s.externalURL})
	s.log().Debug("redirecting to callback", "redirect_url", redirURL)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sess.CookieID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, redirURL, http.StatusSeeOther)
}

// clientCredentials are the client authentication credentials presented at the
// token endpoint, together with the method used to present them.
type clientCredentials struct {
	clientID string
	secret   string
	method   string
}

// parseClientCredentials reads client credentials from the Authorization header
// (client_secret_basic) or the request body (client_secret_post), falling back to
// "none" for public clients. The request form must already be parsed.
func parseClientCredentials(r *http.Request) clientCredentials {
	// RFC 6749 section 2.3.1 wants the Basic credentials form-urlencoded before
	// base64. Client IDs are UUIDs and secrets are base64url here, so nothing this
	// IdP issues needs that decoding step.
	if clientID, secret, ok := r.BasicAuth(); ok {
		return clientCredentials{clientID: clientID, secret: secret, method: "client_secret_basic"}
	}
	if secret := r.Form.Get("client_secret"); secret != "" {
		return clientCredentials{clientID: r.Form.Get("client_id"), secret: secret, method: "client_secret_post"}
	}
	return clientCredentials{clientID: r.Form.Get("client_id"), method: "none"}
}

// authenticateClientLocked verifies presented credentials against the stored
// registration for clientID. Only dynamically registered confidential clients are
// enforced: those are the ones this IdP issued a secret to and whose declared auth
// method it can trust. Callers must hold s.mu.
func (s *server) authenticateClientLocked(clientID string, creds clientCredentials) error {
	reg, known := s.clients[clientID]
	if !known || reg.RegistrationMethod != registrationMethodDynamic {
		// FIXME: Authenticate automatically registered clients. This IdP holds no
		// secret for them and cannot tell a legitimate client from an impostor, so
		// anyone presenting a valid code or refresh token is served.
		return nil
	}
	if reg.TokenEndpointAuthMethod == "none" {
		// A public client authenticates nothing; PKCE is the only binding.
		return nil
	}
	if creds.method != reg.TokenEndpointAuthMethod {
		return fmt.Errorf("client registered with %s but presented %s", reg.TokenEndpointAuthMethod, creds.method)
	}
	if creds.clientID != clientID {
		return fmt.Errorf("credentials are for client %q, grant is for client %q", creds.clientID, clientID)
	}
	if reg.ClientSecret == "" {
		return errors.New("no client secret stored for a confidential client")
	}
	if subtle.ConstantTimeCompare([]byte(creds.secret), []byte(reg.ClientSecret)) != 1 {
		return errors.New("client secret mismatch")
	}
	return nil
}

// writeClientAuthError reports failed client authentication per RFC 6749 section
// 5.2. WWW-Authenticate is required only when the client tried HTTP Basic.
func writeClientAuthError(w http.ResponseWriter, method string) {
	if method == "client_secret_basic" {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	writeOAuthError(w, http.StatusUnauthorized, "invalid_client")
}

func (s *server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	logRequest(s.log(), "token", r)
	_ = r.ParseForm()

	// Credentials are read here but verified only once the grant has established
	// which client is really being authenticated; a request-supplied client_id is
	// never trusted on its own.
	creds := parseClientCredentials(r)
	s.log().Debug("get-token client auth", "auth_method", creds.method, "client_id", creds.clientID)

	grantType := r.Form.Get("grant_type")
	s.log().Debug("get-token grant type", "grant_type", grantType)

	var (
		advertisedSub   string
		username        string
		scope           string
		clientID        string
		cookieID        string
		clientSessionID string
		nonce           string
		idTokenClaims   map[string]any
		accessClaims    map[string]any
	)

	switch grantType {
	case "authorization_code":
		code := r.Form.Get("code")
		_ = r.Form.Get("redirect_uri")
		// FIXME: Validate redirect_uri matches the value stored when the code was issued.
		codeVerifier := r.Form.Get("code_verifier")

		s.mu.Lock()
		meta, ok := s.codeMeta[code]
		if ok {
			delete(s.codeMeta, code)
		}
		s.mu.Unlock()

		if !ok {
			s.log().Warn("get-token invalid code", "code", code)
			writeOAuthError(w, http.StatusForbidden, "invalid_grant")
			return
		}
		// FIXME: Validate that the authorization code has not expired (track issued-at in codeMeta).

		s.log().Debug("get-token valid code", "code", code)
		cookieID = meta.CookieID
		clientID = meta.ClientID
		nonce = meta.Nonce

		s.mu.Lock()
		sess, ok := s.sessions[cookieID]
		s.mu.Unlock()
		if !ok {
			writeOAuthError(w, http.StatusForbidden, "invalid_grant")
			return
		}

		username = sess.Username
		clientSess := getClientSessionByID(sess, clientID)
		if clientSess == nil {
			writeOAuthError(w, http.StatusForbidden, "invalid_grant")
			return
		}

		if clientSess.CodeChallenge != "" {
			s.log().Debug("get-token verifying pkce", "challenge", clientSess.CodeChallenge, "verifier", codeVerifier, "method", clientSess.CodeChallengeMethod)
			switch clientSess.CodeChallengeMethod {
			case "plain":
				if codeVerifier != clientSess.CodeChallenge {
					writeOAuthError(w, http.StatusForbidden, "invalid_grant")
					return
				}
			case "S256":
				digest := sha256.Sum256([]byte(codeVerifier))
				ourCodeChallenge := base64.RawURLEncoding.EncodeToString(digest[:])
				s.log().Debug("pkce s256 challenge comparison", "derived", ourCodeChallenge, "stored", clientSess.CodeChallenge)
				if ourCodeChallenge != clientSess.CodeChallenge {
					writeOAuthError(w, http.StatusForbidden, "invalid_grant")
					return
				}
			default:
				writeOAuthError(w, http.StatusForbidden, "invalid_grant")
				return
			}
		}

		advertisedSub = clientSess.AdvertisedSub
		scope = clientSess.Scope
		idTokenClaims = clientSess.IDTokenClaims
		if idTokenClaims == nil {
			idTokenClaims = s.defaultIDTokenClaims(authContextEntry{
				Sub: sess.Sub, Username: username, Scope: scope,
				ClientID: clientID, Nonce: nonce, RedirectURI: clientSess.RedirectURI,
			})
		}
		clientSessionID = clientSess.SessionID
		accessClaims = clientSess.AccessTokenClaims
		if accessClaims == nil {
			accessClaims = s.defaultAccessTokenClaims(authContextEntry{Scope: scope})
		}
		accessClaims["csid"] = clientSessionID

	case "refresh_token":
		refreshToken := r.Form.Get("refresh_token")
		s.log().Debug("get-token refresh token", "refresh_token", refreshToken)

		refreshClaims, err := s.decodeJWT(refreshToken, s.publicKey)
		if err != nil {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_grant")
			return
		}
		// FIXME: Validate refresh token beyond JWT signature - check for revocation.

		csID, _ := refreshClaims["csid"].(string)
		s.mu.Lock()
		var sess session
		var clientSess *clientSession
		cookieID, sess, clientSess = s.getSessionByClientSessionIDLocked(csID)
		s.mu.Unlock()
		if clientSess == nil {
			s.log().Warn("get-token invalid client session for refresh", "client_session_id", csID)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_grant")
			return
		}

		clientID = clientSess.ClientID
		username = sess.Username
		advertisedSub = clientSess.AdvertisedSub
		scope = clientSess.Scope
		if clientSess.IDTokenClaims != nil {
			nonce, _ = clientSess.IDTokenClaims["nonce"].(string)
		}
		idTokenClaims = clientSess.IDTokenClaims
		if idTokenClaims == nil {
			idTokenClaims = s.defaultIDTokenClaims(authContextEntry{
				Sub: sess.Sub, Username: username, Scope: scope,
				ClientID: clientID, Nonce: nonce, RedirectURI: clientSess.RedirectURI,
			})
		}
		clientSessionID = clientSess.SessionID
		accessClaims = clientSess.AccessTokenClaims
		if accessClaims == nil {
			accessClaims = s.defaultAccessTokenClaims(authContextEntry{Scope: scope})
		}
		accessClaims["csid"] = clientSessionID

	default:
		s.log().Warn("get-token invalid grant type", "grant_type", grantType)
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	// Authentication runs after the grant so that clientID comes from server-side
	// state. An authorization code is already consumed at this point, which makes a
	// failed attempt burn the code - the safe direction for a one-time credential.
	s.mu.Lock()
	authErr := s.authenticateClientLocked(clientID, creds)
	s.mu.Unlock()
	if authErr != nil {
		s.log().Warn("get-token client authentication failed", "client_id", clientID, "error", authErr.Error())
		writeClientAuthError(w, creds.method)
		return
	}

	s.log().Info("issuing tokens", "grant_type", grantType, "client_id", clientID)
	accessAud := dedupeStrings(append([]string{s.externalURL + "/userinfo"}, s.extraAudiences...))
	accessToken, issuedAccessClaims, err := s.issueToken(advertisedSub, accessAud, accessClaims, time.Now().UTC().Add(time.Duration(s.accessTokenLifetime)*time.Second))
	if err != nil {
		http.Error(w, "token issue error", http.StatusInternalServerError)
		return
	}

	response := map[string]any{
		"access_token": accessToken,
		"expires_in":   s.accessTokenLifetime,
		"token_type":   "Bearer",
	}

	var issuedRefreshClaims map[string]any
	if hasScope(scope, "offline_access") {
		refreshAud := dedupeStrings([]string{s.externalURL + "/token"})
		refreshToken, refreshClaims, issueErr := s.issueToken(advertisedSub, refreshAud, map[string]any{
			"token_use": "refresh",
			"csid":      clientSessionID,
		}, time.Now().UTC().Add(time.Duration(s.refreshTokenLifetime)*time.Second))
		if issueErr != nil {
			http.Error(w, "token issue error", http.StatusInternalServerError)
			return
		}
		issuedRefreshClaims = refreshClaims
		response["refresh_token"] = refreshToken
	}

	var issuedIDTokenClaims map[string]any
	if hasScope(scope, "openid") {
		var idToken string
		idToken, issuedIDTokenClaims, err = s.issueToken(advertisedSub, []string{clientID}, idTokenClaims, time.Now().UTC().Add(60*time.Minute))
		if err != nil {
			http.Error(w, "token issue error", http.StatusInternalServerError)
			return
		}
		response["id_token"] = idToken
	}

	// Update the stored session with the full claim sets as last issued so the
	// sessions page reflects exactly what was put in the tokens.
	s.mu.Lock()
	if sess, ok := s.sessions[cookieID]; ok {
		for i := range sess.ClientSessions {
			if sess.ClientSessions[i].SessionID == clientSessionID {
				sess.ClientSessions[i].AdvertisedSub = advertisedSub
				sess.ClientSessions[i].AccessTokenClaims = issuedAccessClaims
				sess.ClientSessions[i].RefreshTokenClaims = issuedRefreshClaims
				if issuedIDTokenClaims != nil {
					sess.ClientSessions[i].IDTokenClaims = issuedIDTokenClaims
				}
				break
			}
		}
		s.sessions[cookieID] = sess
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *server) userinfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	logRequest(s.log(), "userinfo", r)

	claims, err := s.extractAccessToken(r)
	if err != nil {
		s.writeBearerError(w, http.StatusUnauthorized, "invalid_token")
		return
	}

	scope, _ := claims["scope"].(string)
	s.log().Debug("get-userinfo scope", "scope", scope)

	csID, _ := claims["csid"].(string)
	s.mu.Lock()
	_, sess, cs := s.getSessionByClientSessionIDLocked(csID)
	var issued map[string]any
	if cs != nil {
		issued = copyClaims(cs.IDTokenClaims)
	}
	s.mu.Unlock()

	out := map[string]any{}
	sub, _ := claims["sub"].(string)
	out["sub"] = sub
	if issued != nil {
		// Mirror the ID token the client was actually given, so edits made in the
		// session claims editor reach the RP through userinfo too. The subject stays
		// authoritative from the access token: OIDC requires the two to agree.
		for name, value := range issued {
			if _, skip := idTokenOnlyClaims[name]; skip || name == "sub" {
				continue
			}
			if s, ok := claimScopes[name]; ok && !hasScope(scope, s) {
				continue
			}
			out[name] = value
		}
	} else {
		// No ID token was issued for this client session (a non-openid access token),
		// so there is nothing to mirror; derive the claims from the login instead.
		if sess.Username != "" && hasScope(scope, "profile") {
			out["preferred_username"] = sess.Username
			out["name"] = capitalize(sess.Username)
			out["picture"] = fmt.Sprintf("%s/avatars/%d.svg", s.externalURL, avatarIndex(sess.Username))
		}
		if sess.Username != "" && hasScope(scope, "email") {
			out["email"] = s.emailForUsername(sess.Username)
			out["email_verified"] = true
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// idTokenOnlyClaims are ID token mechanics that describe the token rather than the
// end-user, and so are never echoed in a userinfo response.
var idTokenOnlyClaims = map[string]struct{}{
	"iss": {}, "aud": {}, "azp": {}, "exp": {}, "iat": {}, "nbf": {}, "jti": {},
	"nonce": {}, "auth_time": {}, "at_hash": {}, "c_hash": {}, "acr": {}, "amr": {},
}

// claimScopes maps the standard claims this IdP can issue to the scope that must be
// granted for userinfo to return them. Claims not listed here — anything added by
// hand in the claims editor — are returned regardless of scope.
var claimScopes = map[string]string{
	"name":               "profile",
	"preferred_username": "profile",
	"picture":            "profile",
	"email":              "email",
	"email_verified":     "email",
}

func copyClaims(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
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

	s.log().Debug("end-session id token hint claims", "claims", claims)
	sub, _ := claims["sub"].(string)

	s.mu.Lock()
	existingSessionID := s.getSessionByAdvertisedSubLocked(sub)
	if existingSessionID != "" {
		sess := s.sessions[existingSessionID]
		s.mu.Unlock()
		renderTemplate(w, s.templates["endsession"], endsessionData{SessionID: existingSessionID, Subject: sess.Username, RedirURL: redirURL})
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
	cookieID := r.Form.Get("sessionid")
	redirURL := r.Form.Get("redirurl")

	s.log().Info("ending session", "cookie_id", cookieID)
	s.mu.Lock()
	delete(s.sessions, cookieID)
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
		"issuer":                                         s.externalURL,
		"authorization_endpoint":                         s.externalURL + "/authorize",
		"token_endpoint":                                 s.externalURL + "/token",
		"userinfo_endpoint":                              s.externalURL + "/userinfo",
		"jwks_uri":                                       s.externalURL + "/.well-known/jwks.json",
		"end_session_endpoint":                           s.externalURL + "/endsession",
		"response_types_supported":                       []string{"code"},
		"subject_types_supported":                        []string{s.subjectType},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256", "plain"},
		"scopes_supported":                               []string{"openid", "profile", "email", "offline_access"},
		"claims_supported":                               []string{"sub", "name", "picture", "email", "email_verified"},
		"registration_endpoint":                          s.externalURL + "/register",
		"token_endpoint_auth_methods_supported":          supportedTokenEndpointAuthMethods,
		"authorization_response_iss_parameter_supported": true,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(config)
}

func (s *server) issueToken(subject string, audience []string, claims map[string]any, expiry time.Time) (string, map[string]any, error) {
	allClaims := jwt.MapClaims{}
	for k, v := range claims {
		allClaims[k] = v
	}
	if _, hasSub := allClaims["sub"]; !hasSub {
		allClaims["sub"] = subject
	}
	allClaims["iss"] = s.externalURL
	allClaims["aud"] = audience
	allClaims["iat"] = time.Now().UTC().Unix()
	allClaims["exp"] = expiry.UTC().Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, allClaims)
	token.Header["kid"] = "k0"

	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", nil, err
	}

	// Build the full claim map as issued, excluding iat.
	issued := make(map[string]any, len(allClaims))
	for k, v := range allClaims {
		if k == "iat" {
			continue
		}
		issued[k] = v
	}

	return signed, issued, nil
}

// extractAccessToken parses and validates the Authorization: Bearer header,
// then confirms the token carries token_use=access so that ID tokens and
// refresh tokens are rejected even though they are signed by the same key.
func (s *server) extractAccessToken(r *http.Request) (map[string]any, error) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return nil, errors.New("missing or malformed Authorization header")
	}
	claims, err := s.decodeJWT(parts[1], s.publicKey)
	if err != nil {
		return nil, err
	}
	if claims["token_use"] != "access" {
		return nil, errors.New("token is not an access token")
	}
	return claims, nil
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

func writeOAuthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func (s *server) writeBearerError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s", error="%s"`, s.externalURL, code))
	writeOAuthError(w, status, code)
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

// getSessionBySubLocked finds a session by its internal Sub (not the advertised pairwise sub).
func (s *server) getSessionBySubLocked(sub string) (session, bool) {
	for _, sess := range s.sessions {
		if sess.Sub == sub {
			return sess, true
		}
	}
	return session{}, false
}

// getSessionByAdvertisedSubLocked finds a session by the AdvertisedSub stored in any of its
// clientSessions. Used when matching an id_token_hint's sub claim back to an SSO session.
func (s *server) getSessionByAdvertisedSubLocked(advertisedSub string) string {
	for cookieID, sess := range s.sessions {
		for _, cs := range sess.ClientSessions {
			if cs.AdvertisedSub == advertisedSub {
				return cookieID
			}
		}
	}
	return ""
}

// getSessionByClientSessionIDLocked finds a session and clientSession by the clientSession's SessionID.
// Returns the parent CookieID, the session, and a pointer to the matching clientSession (or "" / zero / nil).
func (s *server) getSessionByClientSessionIDLocked(csID string) (string, session, *clientSession) {
	if csID == "" {
		return "", session{}, nil
	}
	for cookieID, sess := range s.sessions {
		for i := range sess.ClientSessions {
			if sess.ClientSessions[i].SessionID == csID {
				return cookieID, sess, &sess.ClientSessions[i]
			}
		}
	}
	return "", session{}, nil
}

func getClientSessionByID(sess session, clientID string) *clientSession {
	for i := range sess.ClientSessions {
		if sess.ClientSessions[i].ClientID == clientID {
			return &sess.ClientSessions[i]
		}
	}
	return nil
}

func upsertClientSession(sessions []clientSession, cs clientSession) []clientSession {
	for i := range sessions {
		if sessions[i].ClientID == cs.ClientID {
			sessions[i] = cs
			return sessions
		}
	}
	return append(sessions, cs)
}

func updateClientSessionPKCE(sess session, clientID, codeChallenge, codeChallengeMethod string) session {
	for i := range sess.ClientSessions {
		if sess.ClientSessions[i].ClientID == clientID {
			sess.ClientSessions[i].CodeChallenge = codeChallenge
			sess.ClientSessions[i].CodeChallengeMethod = codeChallengeMethod
			break
		}
	}
	return sess
}

func updateClientSessionRedirectURI(sess session, clientID, redirectURI string) session {
	for i := range sess.ClientSessions {
		if sess.ClientSessions[i].ClientID == clientID {
			sess.ClientSessions[i].RedirectURI = redirectURI
			break
		}
	}
	return sess
}

func renderTemplate(w http.ResponseWriter, tpl *template.Template, data any) {
	if err := tpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func logRequest(logger *slog.Logger, endpoint string, req *http.Request) {
	if logger == nil {
		logger = slog.Default()
	}

	body, _ := readBody(req)
	logger.Debug("request received", "endpoint", endpoint, "method", req.Method, "path", req.URL.Path)
	for name, values := range req.Header {
		for _, value := range values {
			logger.Debug("request header", "endpoint", endpoint, "name", name, "value", value)
		}
	}
	logger.Debug("request body start", "endpoint", endpoint)
	for _, line := range strings.Split(body, "\n") {
		logger.Debug("request body line", "endpoint", endpoint, "line", line)
	}
}

func (s *server) log() *slog.Logger {
	if s != nil && s.logger != nil {
		return s.logger
	}
	return slog.Default()
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

func claimsToPrettyJSON(claims map[string]any) (string, error) {
	if claims == nil {
		claims = map[string]any{}
	}
	b, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseClaimsJSON(raw string) (map[string]any, error) {
	claims := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (s *server) defaultAccessTokenClaims(ctx authContextEntry) map[string]any {
	return map[string]any{
		"token_use": "access",
		"scope":     ctx.Scope,
	}
}

func hasScope(scope, target string) bool {
	for _, s := range strings.Fields(scope) {
		if s == target {
			return true
		}
	}
	return false
}

func (s *server) defaultIDTokenClaims(ctx authContextEntry) map[string]any {
	claims := map[string]any{
		"sub": s.computeAdvertisedSub(ctx.Sub, sectorIdentifier(ctx.RedirectURI, ctx.ClientID)),
		"azp": ctx.ClientID,
	}
	if ctx.Nonce != "" {
		claims["nonce"] = ctx.Nonce
	}
	if hasScope(ctx.Scope, "profile") {
		claims["name"] = capitalize(ctx.Username)
		claims["preferred_username"] = ctx.Username
		claims["picture"] = fmt.Sprintf("%s/avatars/%d.svg", s.externalURL, avatarIndex(ctx.Username))
	}
	if ctx.Username != "" && hasScope(ctx.Scope, "email") {
		claims["email"] = s.emailForUsername(ctx.Username)
		claims["email_verified"] = true
	}
	return claims
}

// emailForUsername derives a demo email address from the username. This IdP has no
// user store, so the address is synthesized as username@EMAIL_DOMAIN.
func (s *server) emailForUsername(username string) string {
	return username + "@" + s.emailDomain
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

func getenvCSV(name string) []string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func formatExpiryClaim(claims map[string]any) string {
	if claims == nil {
		return "not issued"
	}
	exp, ok := claims["exp"]
	if !ok {
		return "not issued"
	}
	expUnix := intFromAny(exp, 0)
	if expUnix <= 0 {
		return "not issued"
	}
	return time.Unix(int64(expUnix), 0).UTC().Format(time.RFC3339)
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

func getenvDefaultBool(name string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

// sectorIdentifier returns the host component of redirectURI, or clientID as a fallback.
func sectorIdentifier(redirectURI, clientID string) string {
	if u, err := url.Parse(redirectURI); err == nil && u.Host != "" {
		return u.Host
	}
	return clientID
}

// computeAdvertisedSub returns the sub value to advertise to a specific RP.
// In public mode it returns the internal sub unchanged; in pairwise mode it
// returns HMAC-SHA256(pairwiseSalt, sectorID || 0x00 || sub) encoded as base64url.
func (s *server) computeAdvertisedSub(sub, sectorID string) string {
	if s.subjectType != "pairwise" {
		return sub
	}
	mac := hmac.New(sha256.New, s.pairwiseSalt)
	mac.Write([]byte(sectorID))
	mac.Write([]byte{0x00})
	mac.Write([]byte(sub))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
