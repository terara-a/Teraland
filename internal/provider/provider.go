package provider

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type Config struct {
	Issuer         string
	DataDir        string
	TrustAnchors   map[string]jose.JSONWebKeySet
	AuthorityHints []string
	Username       string
	Password       string
	Development    bool
}
type grant struct {
	Client    string
	Redirect  string
	Nonce     string
	Scope     string
	Challenge string
	Subject   string
	Expires   time.Time
}
type authRequest struct {
	Claims  object
	Client  object
	Expires time.Time
	CSRF    string
}
type access struct {
	Subject string
	Expires time.Time
}
type Provider struct {
	config     Config
	signing    jose.JSONWebKey
	encryption jose.JSONWebKey
	client     *http.Client
	mu         sync.Mutex
	codes      map[string]grant
	pars       map[string]authRequest
	logins     map[string]authRequest
	tokens     map[string]access
	replays    map[string]time.Time
}

func New(c Config) (*Provider, error) {
	u, e := url.Parse(c.Issuer)
	if e != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || strings.HasSuffix(c.Issuer, "/") {
		return nil, errors.New("issuer must be an absolute URL without trailing slash, query or fragment")
	}
	if u.Scheme != "https" && !(c.Development && u.Scheme == "http") {
		return nil, errors.New("HTTPS issuer required")
	}
	if c.Username == "" || len(c.Password) < 12 {
		return nil, errors.New("username and password (at least 12 characters) required")
	}
	if c.DataDir == "" {
		return nil, errors.New("data directory required")
	}
	for id, keys := range c.TrustAnchors {
		u, err := url.Parse(id)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(id, "/") || (u.Scheme != "https" && !(c.Development && u.Scheme == "http")) {
			return nil, errors.New("invalid trust anchor identifier")
		}
		if _, err := keySet(keys); err != nil {
			return nil, err
		}
	}
	signing, e := loadKey(filepath.Join(c.DataDir, "signing.jwk"), "sig")
	if e != nil {
		return nil, e
	}
	enc, e := loadKey(filepath.Join(c.DataDir, "encryption.jwk"), "enc")
	if e != nil {
		return nil, e
	}
	p := &Provider{config: c, signing: signing, encryption: enc, codes: map[string]grant{}, pars: map[string]authRequest{}, logins: map[string]authRequest{}, tokens: map[string]access{}, replays: map[string]time.Time{}}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// No redirects or ambient proxy: validate each DNS result before dialing to prevent SSRF/rebinding.
	transport.Proxy = nil
	transport.MaxResponseHeaderBytes = 32 << 10
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			return nil, e
		}
		for _, ip := range ips {
			if !c.Development && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || !ip.IsGlobalUnicast()) {
				return nil, errors.New("non-public federation destination")
			}
		}
		var last error
		for _, ip := range ips {
			conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return conn, nil
			}
			last = e
		}
		return nil, last
	}
	p.client = &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return p, nil
}
func (p *Provider) Metadata() object {
	return object{
		"issuer": p.config.Issuer, "authorization_endpoint": p.config.Issuer + "/authorize", "token_endpoint": p.config.Issuer + "/token", "userinfo_endpoint": p.config.Issuer + "/userinfo", "jwks_uri": p.config.Issuer + "/jwks", "pushed_authorization_request_endpoint": p.config.Issuer + "/par",
		"response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"}, "grant_types_supported": []string{"authorization_code"}, "subject_types_supported": []string{"public"}, "scopes_supported": []string{"openid", "profile"}, "claims_supported": []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "name"},
		"id_token_signing_alg_values_supported": []string{"RS256"}, "request_object_signing_alg_values_supported": []string{"RS256", "PS256", "ES256"}, "token_endpoint_auth_methods_supported": []string{"private_key_jwt"}, "token_endpoint_auth_signing_alg_values_supported": []string{"RS256", "PS256", "ES256"}, "request_parameter_supported": true, "request_uri_parameter_supported": false, "require_signed_request_object": true, "client_registration_types_supported": []string{"automatic"}, "code_challenge_methods_supported": []string{"S256"}, "authorization_response_iss_parameter_supported": true,
		"request_object_encryption_alg_values_supported": []string{"RSA-OAEP-256", "RSA-OAEP"}, "request_object_encryption_enc_values_supported": []string{"A256GCM"},
	}
}
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	base := strings.TrimSuffix(mustURL(p.config.Issuer).Path, "/")
	mux.HandleFunc("GET "+base+"/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, p.Metadata()) })
	mux.HandleFunc("GET "+base+"/.well-known/openid-federation", p.entityConfiguration)
	mux.HandleFunc("GET "+base+"/jwks", func(w http.ResponseWriter, r *http.Request) {
		jsonReply(w, 200, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{p.signing.Public(), p.encryption.Public()}})
	})
	mux.HandleFunc("GET "+base+"/healthz", func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, object{"status": "ok"}) })
	mux.HandleFunc(base+"/authorize", p.authorize)
	mux.HandleFunc("POST "+base+"/par", p.par)
	mux.HandleFunc("POST "+base+"/token", p.token)
	mux.HandleFunc("POST "+base+"/login", p.login)
	mux.HandleFunc("GET "+base+"/userinfo", p.userinfo)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		p.prune()
		mux.ServeHTTP(w, r)
	})
}
func mustURL(s string) *url.URL { u, _ := url.Parse(s); return u }
func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code string) {
	jsonReply(w, status, object{"error": code})
}
func (p *Provider) fetch(ctx context.Context, uri string) ([]byte, error) {
	u, e := url.Parse(uri)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(p.config.Development && u.Scheme == "http")) {
		return nil, errors.New("invalid federation URL")
	}
	r, e := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if e != nil {
		return nil, e
	}
	r.Header.Set("Accept", "application/entity-statement+jwt, application/json")
	resp, e := p.client.Do(r)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("federation HTTP %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if len(b) > 1<<20 {
		return nil, errors.New("federation document too large")
	}
	return b, e
}
func (p *Provider) remember(kind, client, jti string, exp int64) bool {
	if jti == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k := kind + "\x00" + client + "\x00" + jti
	if _, ok := p.replays[k]; ok {
		return false
	}
	if len(p.replays) > 10000 {
		return false
	}
	p.replays[k] = time.Unix(exp, 0)
	return true
}
func (p *Provider) prune() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for k, v := range p.replays {
		if !v.After(now) {
			delete(p.replays, k)
		}
	}
	for k, v := range p.codes {
		if !v.Expires.After(now) {
			delete(p.codes, k)
		}
	}
	for k, v := range p.pars {
		if !v.Expires.After(now) {
			delete(p.pars, k)
		}
	}
	for k, v := range p.logins {
		if !v.Expires.After(now) {
			delete(p.logins, k)
		}
	}
	for k, v := range p.tokens {
		if !v.Expires.After(now) {
			delete(p.tokens, k)
		}
	}
}
func equal(a, b string) bool {
	aa, bb := sha(a), sha(b)
	return subtle.ConstantTimeCompare([]byte(aa), []byte(bb)) == 1
}
