package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type fixture struct {
	p            *Provider
	server       *httptest.Server
	federation   *httptest.Server
	rpID         string
	anchorID     string
	anchor       jose.JSONWebKey
	entityKey    jose.JSONWebKey
	clientKey    jose.JSONWebKey
	mu           sync.Mutex
	badStatement bool
	policy       bool
	metadata     object
	trustExp     int64
}

func testKey(t *testing.T) jose.JSONWebKey {
	t.Helper()
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	return jose.JSONWebKey{Key: k, KeyID: randomID(), Use: "sig", Algorithm: "RS256"}
}
func signed(t *testing.T, k jose.JSONWebKey, typ string, m object) string {
	t.Helper()
	s, e := sign(k, typ, m)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{anchor: testKey(t), entityKey: testKey(t), clientKey: testKey(t)}
	f.federation = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().Unix()
		base := object{"iat": now, "exp": now + 3600}
		var k jose.JSONWebKey
		switch r.URL.Path {
		case "/anchor/.well-known/openid-federation":
			base["iss"] = f.anchorID
			base["sub"] = f.anchorID
			base["jwks"] = publicSet(f.anchor)
			base["metadata"] = object{"federation_entity": object{"federation_fetch_endpoint": f.anchorID + "/fetch"}}
			k = f.anchor
		case "/rp/.well-known/openid-federation":
			base["iss"] = f.rpID
			base["sub"] = f.rpID
			base["jwks"] = publicSet(f.entityKey)
			base["authority_hints"] = []string{f.anchorID}
			base["metadata"] = object{"openid_relying_party": object{"client_registration_types": []string{"automatic"}, "redirect_uris": []string{f.rpID + "/callback"}, "jwks_uri": f.rpID + "/jwks"}}
			f.mu.Lock()
			for name, value := range f.metadata {
				asObject(asObject(base["metadata"])["openid_relying_party"])[name] = value
			}
			f.mu.Unlock()
			k = f.entityKey
		case "/anchor/fetch":
			if r.URL.Query().Get("sub") != f.rpID {
				http.NotFound(w, r)
				return
			}
			base["iss"] = f.anchorID
			base["sub"] = f.rpID
			base["jwks"] = publicSet(f.entityKey)
			k = f.anchor
			f.mu.Lock()
			if f.trustExp != 0 {
				base["exp"] = f.trustExp
			}
			if f.badStatement {
				k = f.entityKey
			}
			if f.policy {
				base["metadata_policy"] = object{"openid_relying_party": object{}}
			}
			f.mu.Unlock()
		case "/rp/jwks":
			jsonReply(w, 200, publicSet(f.clientKey))
			return
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = io.WriteString(w, signed(t, k, "entity-statement+jwt", base))
	}))
	f.rpID = f.federation.URL + "/rp"
	f.anchorID = f.federation.URL + "/anchor"
	// Reserve issuer before constructing Provider so all claims match the server.
	f.server = httptest.NewUnstartedServer(nil)
	issuer := "http://" + f.server.Listener.Addr().String()
	p, e := New(Config{Issuer: issuer, DataDir: t.TempDir(), Development: true, Username: "alice", Password: "test-password-for-alice", TrustAnchors: map[string]jose.JSONWebKeySet{f.anchorID: publicSet(f.anchor)}, AuthorityHints: []string{f.anchorID}})
	if e != nil {
		t.Fatal(e)
	}
	f.p = p
	f.server.Config.Handler = p.Handler()
	f.server.Start()
	t.Cleanup(f.server.Close)
	t.Cleanup(f.federation.Close)
	return f
}
func (f *fixture) claims() object {
	return object{"iss": f.rpID, "client_id": f.rpID, "aud": f.server.URL, "jti": randomID(), "exp": time.Now().Add(5 * time.Minute).Unix(), "response_type": "code", "scope": "openid", "redirect_uri": f.rpID + "/callback", "state": "state-value", "nonce": "nonce-value"}
}
func (f *fixture) assertion(t *testing.T, endpoint string) string {
	return signed(t, f.clientKey, "JWT", object{"iss": f.rpID, "sub": f.rpID, "aud": f.server.URL + endpoint, "exp": time.Now().Add(time.Minute).Unix(), "jti": randomID()})
}
func readJSON(t *testing.T, r *http.Response) object {
	t.Helper()
	defer r.Body.Close()
	var m object
	if e := json.NewDecoder(r.Body).Decode(&m); e != nil {
		t.Fatal(e)
	}
	return m
}
func post(t *testing.T, c *http.Client, uri string, v url.Values) *http.Response {
	t.Helper()
	r, e := c.PostForm(uri, v)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func authForm(id, assertion string) url.Values {
	return url.Values{"client_id": {id}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion}}
}
func (f *fixture) login(t *testing.T, c *http.Client, uri string, postForm url.Values) string {
	t.Helper()
	var r *http.Response
	var e error
	if postForm != nil {
		r = post(t, c, uri, postForm)
	} else {
		r, e = c.Get(uri)
		if e != nil {
			t.Fatal(e)
		}
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("authorize: %d %s", r.StatusCode, body)
	}
	id := regexp.MustCompile(`name="request_id" value="([^"]+)"`).FindStringSubmatch(string(body))
	if len(id) != 2 {
		t.Fatal("login form missing")
	}
	r = post(t, c, f.server.URL+"/login", url.Values{"request_id": {id[1]}, "username": {"alice"}, "password": {"test-password-for-alice"}})
	r.Body.Close()
	if r.StatusCode != 303 {
		t.Fatalf("login: %d", r.StatusCode)
	}
	u, e := url.Parse(r.Header.Get("Location"))
	if e != nil {
		t.Fatal(e)
	}
	if u.Query().Get("state") != "state-value" || u.Query().Get("iss") != f.server.URL {
		t.Fatal("state / issuer missing")
	}
	return u.Query().Get("code")
}
func TestFederatedAuthorizationFlows(t *testing.T) {
	f := newFixture(t)
	for _, mode := range []string{"jar-get", "jar-post", "par", "par-issuer-audience", "encrypted-jar", "encrypted-jar-rsa-oaep", "jar-with-trust-chain", "pkce"} {
		t.Run(mode, func(t *testing.T) {
			jar, _ := cookiejar.New(nil)
			c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			claims := f.claims()
			verifier := strings.Repeat("x", 43)
			if mode == "pkce" {
				claims["code_challenge"] = sha(verifier)
				claims["code_challenge_method"] = "S256"
			}
			raw := signed(t, f.clientKey, "JWT", claims)
			if strings.HasPrefix(mode, "encrypted-jar") {
				alg := jose.RSA_OAEP_256
				if mode == "encrypted-jar-rsa-oaep" {
					alg = jose.RSA_OAEP
				}
				enc, e := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: alg, Key: f.p.encryption.Public()}, (&jose.EncrypterOptions{}).WithContentType("JWT"))
				if e != nil {
					t.Fatal(e)
				}
				obj, e := enc.Encrypt([]byte(raw))
				if e != nil {
					t.Fatal(e)
				}
				raw, e = obj.CompactSerialize()
				if e != nil {
					t.Fatal(e)
				}
			}
			if mode == "jar-with-trust-chain" {
				b, e := f.p.fetch(t.Context(), f.rpID+"/.well-known/openid-federation")
				if e != nil {
					t.Fatal(e)
				}
				opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("trust_chain", []string{string(b)})
				s, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.clientKey}, opts)
				if e != nil {
					t.Fatal(e)
				}
				data, _ := json.Marshal(claims)
				obj, e := s.Sign(data)
				if e != nil {
					t.Fatal(e)
				}
				raw, e = obj.CompactSerialize()
				if e != nil {
					t.Fatal(e)
				}
			}
			params := url.Values{"client_id": {f.rpID}, "request": {raw}, "scope": {"openid"}, "response_type": {"code"}}
			if mode == "par" || mode == "par-issuer-audience" {
				endpoint := "/par"
				if mode == "par-issuer-audience" {
					endpoint = ""
				}
				v := authForm(f.rpID, f.assertion(t, endpoint))
				v.Set("request", raw)
				r := post(t, c, f.server.URL+"/par", v)
				if r.StatusCode != 201 {
					t.Fatalf("par %d: %v", r.StatusCode, readJSON(t, r))
				}
				m := readJSON(t, r)
				params = url.Values{"client_id": {f.rpID}, "request_uri": {text(m, "request_uri")}}
			}
			var code string
			if mode == "jar-post" {
				code = f.login(t, c, f.server.URL+"/authorize", params)
			} else {
				code = f.login(t, c, f.server.URL+"/authorize?"+params.Encode(), nil)
			}
			if code == "" {
				t.Fatal("no code")
			}
			v := authForm(f.rpID, f.assertion(t, "/token"))
			v.Set("grant_type", "authorization_code")
			v.Set("code", code)
			v.Set("redirect_uri", f.rpID+"/callback")
			if mode == "pkce" {
				v.Set("code_verifier", verifier)
			}
			r := post(t, c, f.server.URL+"/token", v)
			if r.StatusCode != 200 {
				t.Fatalf("token %d: %v", r.StatusCode, readJSON(t, r))
			}
			m := readJSON(t, r)
			id, e := verify(text(m, "id_token"), publicSet(f.p.signing), "JWT")
			if e != nil {
				t.Fatal(e)
			}
			if text(id, "nonce") != "nonce-value" || !contains(id["aud"], f.rpID) || text(id, "iss") != f.server.URL || validTimes(id, true) != nil {
				t.Fatalf("invalid ID token: %v", id)
			}
			req, _ := http.NewRequest("GET", f.server.URL+"/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+text(m, "access_token"))
			r, e = c.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			if r.StatusCode != 200 || text(readJSON(t, r), "sub") != text(id, "sub") {
				t.Fatal("userinfo mismatch")
			}
			v.Set("client_assertion", f.assertion(t, "/token"))
			r = post(t, c, f.server.URL+"/token", v)
			if r.StatusCode != 400 || text(readJSON(t, r), "error") != "invalid_grant" {
				t.Fatal("code replay accepted")
			}
		})
	}
}
func TestRejectInvalidRequests(t *testing.T) {
	f := newFixture(t)
	cases := map[string]func(object){"missing-iss": func(m object) { delete(m, "iss") }, "missing-aud": func(m object) { delete(m, "aud") }, "missing-exp": func(m object) { delete(m, "exp") }, "missing-jti": func(m object) { delete(m, "jti") }, "invalid-iss": func(m object) { m["iss"] = "https://attacker.example" }, "invalid-aud": func(m object) { m["aud"] = "https://attacker.example" }, "invalid-client": func(m object) { m["client_id"] = "https://attacker.example" }, "forbidden-sub": func(m object) { m["sub"] = f.rpID }, "expired": func(m object) { m["exp"] = time.Now().Add(-time.Minute).Unix() }, "future-exp": func(m object) { m["exp"] = time.Now().Add(time.Hour).Unix() }, "redirect": func(m object) { m["redirect_uri"] = "https://attacker.example/callback" }, "response-type": func(m object) { m["response_type"] = "token" }, "plain-pkce": func(m object) { m["code_challenge"] = "insecure"; m["code_challenge_method"] = "plain" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := f.claims()
			mutate(m)
			_, e := f.p.requestObject(t.Context(), signed(t, f.clientKey, "JWT", m), f.rpID)
			if e == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	t.Run("wrong-signing-key", func(t *testing.T) {
		if _, e := f.p.requestObject(t.Context(), signed(t, f.entityKey, "JWT", f.claims()), f.rpID); e == nil {
			t.Fatal("federation key accepted as RP signing key")
		}
	})
	t.Run("request-replay", func(t *testing.T) {
		raw := signed(t, f.clientKey, "JWT", f.claims())
		if _, e := f.p.requestObject(t.Context(), raw, f.rpID); e != nil {
			t.Fatal(e)
		}
		if _, e := f.p.requestObject(t.Context(), raw, f.rpID); e == nil {
			t.Fatal("replay accepted")
		}
	})
	t.Run("bad-chain-signature", func(t *testing.T) {
		f.mu.Lock()
		f.badStatement = true
		f.mu.Unlock()
		defer func() { f.mu.Lock(); f.badStatement = false; f.mu.Unlock() }()
		if _, e := f.p.requestObject(t.Context(), signed(t, f.clientKey, "JWT", f.claims()), f.rpID); e == nil {
			t.Fatal("bad chain accepted")
		}
	})
	t.Run("unsupported-policy-fails-closed", func(t *testing.T) {
		f.mu.Lock()
		f.policy = true
		f.mu.Unlock()
		defer func() { f.mu.Lock(); f.policy = false; f.mu.Unlock() }()
		if _, e := f.p.requestObject(t.Context(), signed(t, f.clientKey, "JWT", f.claims()), f.rpID); e == nil {
			t.Fatal("unsupported policy ignored")
		}
	})
	t.Run("unpinned-anchor", func(t *testing.T) {
		original := f.p.config.TrustAnchors
		f.p.config.TrustAnchors = map[string]jose.JSONWebKeySet{}
		defer func() { f.p.config.TrustAnchors = original }()
		if _, e := f.p.requestObject(t.Context(), signed(t, f.clientKey, "JWT", f.claims()), f.rpID); e == nil {
			t.Fatal("unpinned anchor accepted")
		}
	})
}
func TestDiscoveryAndKeyPersistence(t *testing.T) {
	f := newFixture(t)
	r, e := http.Get(f.server.URL + "/.well-known/openid-federation")
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	m, e := validateEntity(string(b), f.server.URL)
	if e != nil {
		t.Fatal(e)
	}
	if text(asObject(asObject(m["metadata"])["openid_provider"]), "issuer") != f.server.URL {
		t.Fatal("missing provider metadata")
	}
	r, e = http.Get(f.server.URL + "/jwks")
	if e != nil {
		t.Fatal(e)
	}
	keys, e := keySet(readJSON(t, r))
	if e != nil || len(keys.Keys) != 2 {
		t.Fatal("invalid public JWKS")
	}
	for _, k := range keys.Keys {
		if !k.IsPublic() {
			t.Fatal("private key exposed")
		}
	}
	p, e := New(f.p.config)
	if e != nil {
		t.Fatal(e)
	}
	if p.signing.KeyID != f.p.signing.KeyID {
		t.Fatal("signing key changed on restart")
	}
}
func TestTokenAuthenticationAndPARBinding(t *testing.T) {
	f := newFixture(t)
	c := http.DefaultClient
	v := authForm(f.rpID, f.assertion(t, "/wrong-endpoint"))
	v.Set("request", signed(t, f.clientKey, "JWT", f.claims()))
	r := post(t, c, f.server.URL+"/par", v)
	if r.StatusCode != 401 {
		t.Fatalf("wrong assertion audience accepted: %d", r.StatusCode)
	}
	r.Body.Close()
	v = authForm(f.rpID, f.assertion(t, "/par"))
	v.Set("request", signed(t, f.clientKey, "JWT", f.claims()))
	r = post(t, c, f.server.URL+"/par", v)
	if r.StatusCode != 201 {
		t.Fatal(readJSON(t, r))
	}
	m := readJSON(t, r)
	r, e := c.Get(f.server.URL + "/authorize?" + url.Values{"client_id": {"https://attacker.example"}, "request_uri": {text(m, "request_uri")}}.Encode())
	if e != nil {
		t.Fatal(e)
	}
	if r.StatusCode != 400 {
		t.Fatal("PAR client binding bypassed")
	}
	r.Body.Close()
	assertion := f.assertion(t, "/token")
	v = authForm(f.rpID, assertion)
	_ = formForAuth(t, v, func(req *http.Request) {
		rp, e := f.p.relyingParty(t.Context(), f.rpID)
		if e != nil {
			t.Fatal(e)
		}
		if !f.p.authenticate(req, rp, "/token") {
			t.Fatal("valid assertion rejected")
		}
		if f.p.authenticate(req, rp, "/token") {
			t.Fatal("assertion replay accepted")
		}
	})
}
func formForAuth(t *testing.T, v url.Values, fn func(*http.Request)) bool {
	t.Helper()
	r := httptest.NewRequest("POST", "/token", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !form(r) {
		t.Fatal("form parse")
	}
	fn(r)
	return true
}
func TestLoginCSRFAndCredentials(t *testing.T) {
	f := newFixture(t)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, bad := range []string{"csrf", "password", "origin"} {
		t.Run(bad, func(t *testing.T) {
			params := url.Values{"client_id": {f.rpID}, "request": {signed(t, f.clientKey, "JWT", f.claims())}}
			r, e := c.Get(f.server.URL + "/authorize?" + params.Encode())
			if e != nil {
				t.Fatal(e)
			}
			b, _ := io.ReadAll(r.Body)
			r.Body.Close()
			id := regexp.MustCompile(`name="request_id" value="([^"]+)"`).FindStringSubmatch(string(b))
			if len(id) != 2 {
				t.Fatal(string(b))
			}
			v := url.Values{"request_id": {id[1]}, "username": {"alice"}, "password": {"test-password-for-alice"}}
			if bad == "password" {
				v.Set("password", "wrong")
			}
			req, _ := http.NewRequest("POST", f.server.URL+"/login", strings.NewReader(v.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if bad == "origin" {
				req.Header.Set("Origin", "https://attacker.example")
			}
			client := c
			if bad == "csrf" {
				client = &http.Client{}
			}
			r, e = client.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Body.Close()
			if r.StatusCode < 400 {
				t.Fatal("invalid login accepted")
			}
		})
	}
}
func TestProductionConfiguration(t *testing.T) {
	_, e := New(Config{Issuer: "http://localhost:8080", DataDir: t.TempDir(), Username: "alice", Password: "a-long-test-password"})
	if e == nil {
		t.Fatal("HTTP issuer accepted in production")
	}
	f := newFixture(t)
	cfg := f.p.config
	cfg.Development = false
	cfg.Issuer = "https://op.example"
	cfg.TrustAnchors = nil
	production, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.p = production
	if _, e = f.p.fetch(t.Context(), "http://127.0.0.1/"); e == nil {
		t.Fatal("HTTP SSRF accepted")
	}
	if _, e = f.p.fetch(t.Context(), "https://127.0.0.1/"); e == nil || !strings.Contains(e.Error(), "non-public federation destination") {
		t.Fatal("private HTTPS SSRF accepted")
	}
}
