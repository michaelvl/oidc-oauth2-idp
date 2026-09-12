package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// clientIDMetadataMaxBytes caps both the metadata document and any jwks_uri
	// response. The draft (section 4) recommends a limit around 5 KB.
	clientIDMetadataMaxBytes = 5120

	// Bounds on a document-supplied Cache-Control max-age. A document that asks to
	// be cached for a second would turn every /authorize into an outbound fetch; one
	// asking for a week would outlive any key rotation this IdP could notice.
	clientIDMetadataMinTTL = 60 * time.Second
	clientIDMetadataMaxTTL = 24 * time.Hour

	clientIDMetadataDefaultTTL     = 900 * time.Second
	clientIDMetadataDefaultTimeout = 5 * time.Second
)

// clientIDMetadataAuthMethods are the only token endpoint authentication methods a
// metadata document may declare. Every shared-secret method is forbidden by draft
// section 3: there is no registration step in which a secret could be agreed.
var clientIDMetadataAuthMethods = []string{"none", "private_key_jwt"}

// clientIDMetadataEntry is one cached metadata document. keys is resolved lazily,
// on the first private_key_jwt assertion from this client, and is discarded with
// the rest of the entry when it expires.
type clientIDMetadataEntry struct {
	reg       clientRegistration
	keys      *clientKeySet
	expiresAt time.Time
}

// clientIDMetadataURL decides whether clientID is a Client Identifier URL as
// defined by draft-ietf-oauth-client-id-metadata-document-02 section 2. A
// client_id that fails any of these rules is not a metadata document URL at all
// and falls through to this IdP's automatic registration, unchanged.
//
// The returned URL is for inspection only. The client's identity is the original
// request string: the draft requires simple string comparison per RFC 3986
// section 6.2.1, which makes https://ex.com/c and https://ex.com:443/c two
// distinct clients that must never be normalized together.
func clientIDMetadataURL(clientID string) (*url.URL, error) {
	u, err := url.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("client_id %q is not a valid URL", clientID)
	}

	switch u.Scheme {
	// draft-ietf-oauth-client-id-metadata-document-02 section 2 requires the https
	// scheme. http is accepted here because this IdP is a local-testing tool and
	// clients typically serve their metadata document over plain HTTP on localhost.
	// Do not carry this relaxation into anything resembling production.
	case "https", "http":
	default:
		return nil, fmt.Errorf("client_id %q must use the https or http scheme", clientID)
	}

	if u.User != nil {
		return nil, fmt.Errorf("client_id %q must not contain a userinfo component", clientID)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("client_id %q must contain a host", clientID)
	}
	if u.Path == "" || u.Path == "/" {
		return nil, fmt.Errorf("client_id %q must contain a path component", clientID)
	}
	for _, segment := range strings.Split(u.EscapedPath(), "/") {
		if segment == "." || segment == ".." {
			return nil, fmt.Errorf("client_id %q must not contain . or .. path segments", clientID)
		}
	}
	if u.Fragment != "" || strings.Contains(clientID, "#") {
		return nil, fmt.Errorf("client_id %q must not contain a fragment", clientID)
	}
	return u, nil
}

// isClientIDMetadataDocumentURL reports whether clientID should be resolved as a
// metadata document URL, logging the draft's SHOULD NOT on query components.
func (s *server) isClientIDMetadataDocumentURL(clientID string) bool {
	u, err := clientIDMetadataURL(clientID)
	if err != nil {
		return false
	}
	if u.RawQuery != "" {
		s.log().Warn("client id metadata document URL carries a query component", "client_id", clientID)
	}
	return true
}

// resolveClientIDMetadata returns the registration for a Client Identifier URL,
// fetching and validating the document when nothing usable is cached.
func (s *server) resolveClientIDMetadata(clientID string) (clientRegistration, error) {
	s.mu.Lock()
	entry, cached := s.clientIDMetadata[clientID]
	s.mu.Unlock()
	if cached && time.Now().Before(entry.expiresAt) {
		return entry.reg, nil
	}

	// Fetched with s.mu released: holding it across an outbound request would stall
	// every other request against this IdP. Two concurrent misses may therefore both
	// fetch and both store, which costs a duplicate request and nothing else - not
	// worth a singleflight here.
	reg, ttl, err := s.fetchClientIDMetadata(clientID)
	if err != nil {
		// Draft section 4: an error response or a malformed document is not cached.
		return clientRegistration{}, err
	}

	s.mu.Lock()
	if s.clientIDMetadata == nil {
		s.clientIDMetadata = map[string]clientIDMetadataEntry{}
	}
	// Keep the original issue time so /clients keeps ordering this registration by
	// when the IdP first saw it rather than by its last refresh.
	if previous, ok := s.clients[clientID]; ok && previous.RegistrationMethod == registrationMethodClientIDMetadataDocument && previous.ClientIDIssuedAt != 0 {
		reg.ClientIDIssuedAt = previous.ClientIDIssuedAt
	}
	s.clientIDMetadata[clientID] = clientIDMetadataEntry{reg: reg, expiresAt: time.Now().Add(ttl)}
	if s.clients == nil {
		s.clients = map[string]clientRegistration{}
	}
	s.clients[clientID] = reg
	s.mu.Unlock()

	s.log().Info("resolved client id metadata document", "client_id", clientID, "ttl_seconds", int(ttl.Seconds()), "token_endpoint_auth_method", reg.TokenEndpointAuthMethod)
	return reg, nil
}

// fetchClientIDMetadata performs the outbound GET and validates the document.
func (s *server) fetchClientIDMetadata(clientID string) (clientRegistration, time.Duration, error) {
	body, header, err := s.fetchGuardedJSON(clientID)
	if err != nil {
		return clientRegistration{}, 0, err
	}

	reg, err := validateClientIDMetadata(clientID, body)
	if err != nil {
		return clientRegistration{}, 0, err
	}
	return reg, s.clientIDMetadataTTLFrom(header.Get("Cache-Control")), nil
}

// validateClientIDMetadata turns a fetched document into a registration, applying
// draft section 3's restrictions on top of this IdP's existing RFC 7591 checks.
func validateClientIDMetadata(clientID string, body []byte) (clientRegistration, error) {
	// Decoded twice on purpose: the typed struct models only the subset of the RFC
	// 7591 registry this IdP understands, so the forbidden keys have to be spotted
	// in the raw object. Unknown members stay tolerated either way.
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return clientRegistration{}, fmt.Errorf("client id metadata document is not a JSON object: %w", err)
	}

	documentClientID, _ := raw["client_id"].(string)
	if documentClientID == "" {
		return clientRegistration{}, errors.New("client id metadata document has no client_id")
	}
	// Simple string comparison, per draft section 3.
	if documentClientID != clientID {
		return clientRegistration{}, fmt.Errorf("client id metadata document declares client_id %q but was fetched from %q", documentClientID, clientID)
	}
	for _, forbidden := range []string{"client_secret", "client_secret_expires_at"} {
		if _, present := raw[forbidden]; present {
			return clientRegistration{}, fmt.Errorf("client id metadata document must not contain %s", forbidden)
		}
	}

	var reg clientRegistration
	if err := json.Unmarshal(body, &reg); err != nil {
		return clientRegistration{}, fmt.Errorf("client id metadata document is not valid client metadata: %w", err)
	}

	if regErr := normalizeRegistration(&reg, clientIDMetadataAuthMethods, "none"); regErr != nil {
		return clientRegistration{}, fmt.Errorf("client id metadata document rejected: %s", regErr.description)
	}
	if reg.TokenEndpointAuthMethod == "private_key_jwt" && len(reg.Jwks) == 0 && reg.JwksURI == "" {
		return clientRegistration{}, errors.New("client id metadata document declares private_key_jwt but carries neither jwks nor jwks_uri")
	}

	reg.ClientID = clientID
	reg.ClientIDIssuedAt = time.Now().UTC().Unix()
	reg.ClientSecret = ""
	reg.ClientSecretExpiresAt = nil
	reg.RegistrationMethod = registrationMethodClientIDMetadataDocument
	return reg, nil
}

// clientIDMetadataTTLFrom derives a cache lifetime from a Cache-Control header,
// falling back to the configured default when it carries no usable max-age.
func (s *server) clientIDMetadataTTLFrom(cacheControl string) time.Duration {
	fallback := s.clientIDMetadataTTL
	if fallback <= 0 {
		fallback = clientIDMetadataDefaultTTL
	}

	for _, directive := range strings.Split(cacheControl, ",") {
		name, value, found := strings.Cut(strings.TrimSpace(directive), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "max-age") {
			continue
		}
		seconds, err := strconv.Atoi(strings.Trim(strings.TrimSpace(value), `"`))
		if err != nil || seconds <= 0 {
			continue
		}
		return min(max(time.Duration(seconds)*time.Second, clientIDMetadataMinTTL), clientIDMetadataMaxTTL)
	}
	return fallback
}

// fetchGuardedJSON GETs a JSON document under every constraint draft section 4
// puts on the metadata fetch: exactly 200, no redirects followed, a JSON content
// type, and a hard size cap. It is used for jwks_uri too, which the draft treats
// as the same kind of client-controlled outbound request.
func (s *server) fetchGuardedJSON(rawURL string) ([]byte, http.Header, error) {
	timeout := s.clientIDMetadataTimeout
	if timeout <= 0 {
		timeout = clientIDMetadataDefaultTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("could not build request for %q: %w", rawURL, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.metadataHTTPClient(timeout).Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching %q failed: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Draft section 4 wants exactly 200. With redirects unfollowed a 3xx arrives
	// here as-is and fails this check, which is the intent: a redirect would let a
	// document point the fetch somewhere the client identifier never named.
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("fetching %q returned status %d", rawURL, resp.StatusCode)
	}

	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, nil, fmt.Errorf("fetching %q returned an unparsable content type %q", rawURL, resp.Header.Get("Content-Type"))
	}
	if mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
		return nil, nil, fmt.Errorf("fetching %q returned content type %q, want JSON", rawURL, mediaType)
	}

	// One byte past the cap tells an oversized body from one that merely fills it.
	// An overrun is an error rather than a truncation: half a document is not a
	// document.
	body, err := io.ReadAll(io.LimitReader(resp.Body, clientIDMetadataMaxBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("reading %q failed: %w", rawURL, err)
	}
	if len(body) > clientIDMetadataMaxBytes {
		return nil, nil, fmt.Errorf("fetching %q returned more than %d bytes", rawURL, clientIDMetadataMaxBytes)
	}
	return body, resp.Header, nil
}

// metadataHTTPClient builds the SSRF-guarded client used for every outbound fetch
// a client_id can trigger. It is built per request rather than cached on the
// server so that the loopback allowance is read at fetch time, which is what lets
// tests flip it on a server literal.
//
// That per-request construction is also why keep-alives are off. A transport built
// here is unreachable the moment the fetch returns, so any connection it parked in
// its idle pool would be held open - the zero value of IdleConnTimeout is no
// timeout at all - until the process exited, one leaked descriptor per fetch. These
// fetches are cached for a TTL and so are rare by design; a handshake each time is
// the cheaper side of that trade, and it leaves a hostile client nothing to occupy.
func (s *server) metadataHTTPClient(timeout time.Duration) *http.Client {
	allowLoopback := s.allowLoopbackMetadataFetch
	dialer := &net.Dialer{
		Timeout: timeout,
		// The guard runs against the resolved IP actually being dialed, not against
		// the hostname: a name check would still be rebindable to a private address
		// between resolution and connection.
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("could not parse dial address %q: %w", address, err)
			}
			return checkFetchAddress(net.ParseIP(host), allowLoopback)
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ssrfBlockedCIDRs are the RFC 6890 special-use ranges that net.IP does not
// already classify with a helper.
var ssrfBlockedCIDRs = mustParseCIDRs(
	"100.64.0.0/10",      // shared address space
	"192.0.0.0/24",       // IETF protocol assignments
	"192.0.2.0/24",       // TEST-NET-1
	"198.18.0.0/15",      // benchmarking
	"198.51.100.0/24",    // TEST-NET-2
	"203.0.113.0/24",     // TEST-NET-3
	"240.0.0.0/4",        // reserved
	"255.255.255.255/32", // limited broadcast
	"::/128",             // unspecified
	"100::/64",           // discard-only
	"2001:db8::/32",      // documentation
)

// checkFetchAddress implements draft section 7: an authorization server must not
// dereference a client identifier that resolves to a special-use address.
func checkFetchAddress(ip net.IP, allowLoopback bool) error {
	if ip == nil {
		return errors.New("refusing to dial an address that is not an IP")
	}

	if ip.IsLoopback() {
		// The draft's development exception, verbatim: loopback - and loopback alone
		// - is reachable when the authorization server is itself on a loopback
		// address. IDP_EXTERNAL_URL decides that, so a real deployment closes the
		// exception without any separate configuration.
		if allowLoopback {
			return nil
		}
		return fmt.Errorf("refusing to dial loopback address %s", ip)
	}
	if ip.IsUnspecified() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return fmt.Errorf("refusing to dial special-use address %s", ip)
	}
	for _, blocked := range ssrfBlockedCIDRs {
		if blocked.Contains(ip) {
			return fmt.Errorf("refusing to dial special-use address %s in %s", ip, blocked)
		}
	}
	return nil
}

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("invalid blocked CIDR %q: %v", cidr, err))
		}
		out = append(out, network)
	}
	return out
}

// externalURLIsLoopback reports whether this IdP is reachable on a loopback
// address, which is what enables the draft's development exception.
func externalURLIsLoopback(externalURL string) bool {
	u, err := url.Parse(externalURL)
	if err != nil {
		return false
	}
	hostname := u.Hostname()
	if hostname == "localhost" {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}
