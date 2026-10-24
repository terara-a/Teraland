package provider

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func signAlgorithm(t *testing.T, k jose.JSONWebKey, alg jose.SignatureAlgorithm, claims object) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.KeyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: k.Key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	j, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := j.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestRegisteredSigningAlgorithms(t *testing.T) {
	f := newFixture(t)
	// A key without alg can verify both signatures; client metadata must still
	// restrict which of those signatures this registration allows.
	f.clientKey.Algorithm = ""
	for _, name := range []string{"request_object_signing_alg", "token_endpoint_auth_signing_alg"} {
		t.Run(name, func(t *testing.T) {
			f.mu.Lock()
			f.metadata = object{name: "PS256"}
			f.mu.Unlock()
			for _, alg := range []jose.SignatureAlgorithm{jose.RS256, jose.PS256} {
				t.Run(string(alg), func(t *testing.T) {
					accepted := false
					if name == "request_object_signing_alg" {
						_, err := f.p.requestObject(t.Context(), signAlgorithm(t, f.clientKey, alg, f.claims()), f.rpID)
						accepted = err == nil
					} else {
						rp, err := f.p.relyingParty(t.Context(), f.rpID)
						if err != nil {
							t.Fatal(err)
						}
						assertion := signAlgorithm(t, f.clientKey, alg, object{"iss": f.rpID, "sub": f.rpID, "aud": f.server.URL + "/token", "exp": time.Now().Add(time.Minute).Unix(), "jti": randomID()})
						formForAuth(t, authForm(f.rpID, assertion), func(r *http.Request) { accepted = f.p.authenticate(r, rp, "/token") })
					}
					if accepted != (alg == jose.PS256) {
						t.Fatalf("registered PS256, received %s: accepted=%v", alg, accepted)
					}
				})
			}
		})
	}
}
func TestRejectUnsupportedCryptoRegistration(t *testing.T) {
	f := newFixture(t)
	for name, value := range (object{"id_token_signed_response_alg": "ES256", "id_token_encrypted_response_alg": "RSA-OAEP-256", "id_token_encrypted_response_enc": "A256GCM", "request_object_signing_alg": "none", "token_endpoint_auth_signing_alg": "HS256"}) {
		t.Run(name, func(t *testing.T) {
			f.mu.Lock()
			f.metadata = object{name: value}
			f.mu.Unlock()
			if _, err := f.p.relyingParty(t.Context(), f.rpID); err == nil {
				t.Fatal("unsupported cryptographic requirements accepted")
			}
		})
	}
	f.mu.Lock()
	f.metadata = object{"id_token_signed_response_alg": "RS256"}
	f.mu.Unlock()
	if _, err := f.p.relyingParty(t.Context(), f.rpID); err != nil {
		t.Fatal(err)
	}
}
func TestPARPreservesTrustExpiry(t *testing.T) {
	f := newFixture(t)
	expiry := time.Now().Add(15 * time.Second).Unix()
	f.mu.Lock()
	f.trustExp = expiry
	f.mu.Unlock()
	v := authForm(f.rpID, f.assertion(t, "/par"))
	v.Set("request", signed(t, f.clientKey, "JWT", f.claims()))
	r := post(t, http.DefaultClient, f.server.URL+"/par", v)
	if r.StatusCode != 201 {
		t.Fatal(readJSON(t, r))
	}
	m := readJSON(t, r)
	if number(m, "expires_in") <= 0 || number(m, "expires_in") > 15 {
		t.Fatalf("PAR exceeded trust lifetime: %v", m)
	}
	uri := text(m, "request_uri")
	f.p.mu.Lock()
	a := f.p.pars[uri]
	f.p.mu.Unlock()
	if a.Expires.Unix() != expiry {
		t.Fatalf("trust expiration lost: %s", a.Expires)
	}
	// Simulate reaching the deadline without a wall-clock sleep.
	a.Expires = time.Now().Add(-time.Second)
	f.p.mu.Lock()
	f.p.pars[uri] = a
	f.p.mu.Unlock()
	r, err := http.Get(f.server.URL + "/authorize?" + url.Values{"client_id": {f.rpID}, "request_uri": {uri}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatal("expired PAR was redeemable")
	}
}
func TestConcurrentLoginsAndCallbackPolicy(t *testing.T) {
	f := newFixture(t)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var ids []string
	for range 2 {
		params := url.Values{"client_id": {f.rpID}, "request": {signed(t, f.clientKey, "JWT", f.claims())}}
		r, err := c.Get(f.server.URL + "/authorize?" + params.Encode())
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal(string(body))
		}
		// Chromium applies form-action to the login POST's subsequent redirect too.
		policy := r.Header.Get("Content-Security-Policy")
		origin := mustURL(f.rpID)
		if !strings.Contains(policy, "form-action 'self' "+origin.Scheme+"://"+origin.Host+";") {
			t.Fatalf("validated RP callback blocked by CSP: %s", policy)
		}
		id := regexp.MustCompile(`name="request_id" value="([^"]+)"`).FindStringSubmatch(string(body))
		if len(id) != 2 {
			t.Fatal("missing login request")
		}
		ids = append(ids, id[1])
	}
	for _, id := range ids {
		r := post(t, c, f.server.URL+"/login", url.Values{"request_id": {id}, "username": {"alice"}, "password": {"test-password-for-alice"}})
		r.Body.Close()
		if r.StatusCode != 303 {
			t.Fatalf("concurrent login failed: %d", r.StatusCode)
		}
		if !strings.HasPrefix(r.Header.Get("Location"), f.rpID+"/callback?") {
			t.Fatal("unexpected callback")
		}
	}
}
func TestAuthenticationTimeAndPostUserInfo(t *testing.T) {
	f := newFixture(t)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	code := f.login(t, c, f.server.URL+"/authorize?"+url.Values{"client_id": {f.rpID}, "request": {signed(t, f.clientKey, "JWT", f.claims())}}.Encode(), nil)
	f.p.mu.Lock()
	g := f.p.codes[code]
	if g.AuthTime == 0 {
		f.p.mu.Unlock()
		t.Fatal("authentication time not recorded at login")
	}
	authTime := g.AuthTime - 120
	g.AuthTime = authTime
	f.p.codes[code] = g
	f.p.mu.Unlock()
	v := authForm(f.rpID, f.assertion(t, "/token"))
	v.Set("grant_type", "authorization_code")
	v.Set("code", code)
	v.Set("redirect_uri", f.rpID+"/callback")
	r := post(t, c, f.server.URL+"/token", v)
	if r.StatusCode != 200 {
		t.Fatal(readJSON(t, r))
	}
	m := readJSON(t, r)
	claims, err := verify(text(m, "id_token"), publicSet(f.p.signing), "JWT")
	if err != nil {
		t.Fatal(err)
	}
	if number(claims, "auth_time") != authTime || number(claims, "iat") <= authTime {
		t.Fatalf("auth_time replaced by token issuance time: %v", claims)
	}
	req, _ := http.NewRequest("POST", f.server.URL+"/userinfo", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+text(m, "access_token"))
	r, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 200 {
		t.Fatalf("POST userinfo status %d", r.StatusCode)
	}
	if text(readJSON(t, r), "sub") != text(claims, "sub") {
		t.Fatal("POST userinfo subject mismatch")
	}
	req, _ = http.NewRequest("POST", f.server.URL+"/userinfo", nil)
	r, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatal("unauthenticated POST userinfo accepted")
	}
}

func TestFederationSharedAddressSpace(t *testing.T) {
	f := newFixture(t)
	cfg := f.p.config
	cfg.Development = false
	cfg.Issuer = "https://op.example"
	cfg.TrustAnchors = nil
	production, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	transport := production.client.Transport.(*http.Transport)
	for _, address := range []string{"100.64.0.0", "100.64.0.1", "100.100.100.100", "100.127.255.255", "::ffff:100.64.0.0", "::ffff:100.100.100.100", "::ffff:100.127.255.255", "127.0.0.1", "::ffff:127.0.0.1", "::1", "10.0.0.1", "::ffff:10.0.0.1", "fc00::1", "fe80::1"} {
		t.Run(address, func(t *testing.T) {
			conn, err := transport.DialContext(t.Context(), "tcp", net.JoinHostPort(address, "443"))
			if conn != nil {
				conn.Close()
				t.Fatal("non-public destination connected")
			}
			if err == nil || err.Error() != "non-public federation destination" {
				t.Fatalf("destination was not rejected before connecting: %v", err)
			}
		})
	}
	// Adjacent global ranges must not be accidentally included in the /10 block.
	for _, address := range []string{"100.63.255.255", "100.128.0.0", "::ffff:100.63.255.255", "::ffff:100.128.0.0", "8.8.8.8", "2606:4700:4700::1111"} {
		if !publicFederationAddress(netip.MustParseAddr(address)) {
			t.Errorf("public address incorrectly rejected: %s", address)
		}
	}
}
