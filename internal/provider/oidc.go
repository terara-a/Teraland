package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"net/http"
	"strings"
	"time"
)

func splitScope(s string) []string { return strings.Fields(s) }
func form(r *http.Request) bool {
	if r.Method != "GET" && r.Method != "POST" {
		return false
	}
	if r.Method == "POST" && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return false
	}
	if r.ParseForm() != nil {
		return false
	}
	for _, v := range r.Form {
		if len(v) != 1 {
			return false
		}
	}
	return true
}
func (p *Provider) authenticate(r *http.Request, rp object, endpoint string) bool {
	if r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return false
	}
	ks, e := keySet(rp["jwks"])
	if e != nil {
		return false
	}
	m, e := verifyRegistered(r.Form.Get("client_assertion"), ks, text(rp, "token_endpoint_auth_signing_alg"))
	if e != nil || validTimes(m, false) != nil {
		return false
	}
	id := text(rp, "client_id")
	audienceOK := contains(m["aud"], p.config.Issuer) || contains(m["aud"], p.config.Issuer+endpoint) || (endpoint == "/par" && contains(m["aud"], p.config.Issuer+"/token"))
	if text(m, "iss") != id || text(m, "sub") != id || !audienceOK || number(m, "exp") > time.Now().Add(10*time.Minute).Unix() {
		return false
	}
	return p.remember("assertion", id, text(m, "jti"), number(m, "exp"))
}
func (p *Provider) par(w http.ResponseWriter, r *http.Request) {
	if !form(r) || r.Form.Get("request_uri") != "" {
		fail(w, 400, "invalid_request")
		return
	}
	a, e := p.requestObject(r.Context(), r.Form.Get("request"), r.Form.Get("client_id"))
	if e != nil {
		requestFailure(w, e)
		return
	}
	if !p.authenticate(r, a.Client, "/par") {
		fail(w, 401, "invalid_client")
		return
	}
	if limit := time.Now().Add(90 * time.Second); limit.Before(a.Expires) {
		a.Expires = limit
	}
	uri := "urn:ietf:params:oauth:request_uri:" + randomID()
	p.mu.Lock()
	if len(p.pars) > 10000 {
		p.mu.Unlock()
		fail(w, 503, "temporarily_unavailable")
		return
	}
	p.pars[uri] = a
	p.mu.Unlock()
	jsonReply(w, 201, object{"request_uri": uri, "expires_in": int(time.Until(a.Expires).Seconds())})
}
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	if !form(r) {
		fail(w, 400, "invalid_request")
		return
	}
	var a authRequest
	if uri := r.Form.Get("request_uri"); uri != "" {
		p.mu.Lock()
		var ok bool
		a, ok = p.pars[uri]
		if ok && text(a.Claims, "client_id") == r.Form.Get("client_id") {
			delete(p.pars, uri)
		}
		p.mu.Unlock()
		if !ok || !a.Expires.After(time.Now()) || text(a.Claims, "client_id") != r.Form.Get("client_id") || r.Form.Get("request") != "" {
			fail(w, 400, "invalid_request_uri")
			return
		}
	} else {
		var e error
		a, e = p.requestObject(r.Context(), r.Form.Get("request"), r.Form.Get("client_id"))
		if e != nil {
			requestFailure(w, e)
			return
		}
		for _, k := range []string{"scope", "response_type"} {
			if v := r.Form.Get(k); v != "" && v != text(a.Claims, k) {
				fail(w, 400, "invalid_request")
				return
			}
		}
	}
	if contains(splitScope(text(a.Claims, "prompt")), "none") {
		p.redirect(w, r, a, object{"error": "login_required"})
		return
	}
	id := randomID()
	a.CSRF = randomID()
	p.mu.Lock()
	if len(p.logins) > 10000 {
		p.mu.Unlock()
		fail(w, 503, "temporarily_unavailable")
		return
	}
	p.logins[id] = a
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "teraland_login_" + id, Value: a.CSRF, Path: mustURL(p.config.Issuer).Path + "/login", HttpOnly: true, Secure: !p.config.Development, SameSite: http.SameSiteStrictMode, MaxAge: 300})
	callback := mustURL(text(a.Claims, "redirect_uri"))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self' "+callback.Scheme+"://"+callback.Host+"; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginPage.Execute(w, object{"Action": p.config.Issuer + "/login", "ID": id, "Client": text(a.Claims, "client_id")})
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html><html lang="ja"><meta charset="utf-8"><title>Teraland ログイン</title><h1>Teraland</h1><p>{{.Client}} にログインします。</p><form method="post" action="{{.Action}}"><input type="hidden" name="request_id" value="{{.ID}}"><p><label>ユーザー名 <input name="username" autocomplete="username" required></label></p><p><label>パスワード <input type="password" name="password" autocomplete="current-password" required></label></p><button type="submit">ログインして許可</button></form></html>`))

func (p *Provider) login(w http.ResponseWriter, r *http.Request) {
	if !form(r) {
		fail(w, 400, "invalid_request")
		return
	}
	id := r.Form.Get("request_id")
	cookie, e := r.Cookie("teraland_login_" + id)
	if e != nil {
		fail(w, 400, "invalid_request")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u := mustURL(p.config.Issuer)
		if origin != u.Scheme+"://"+u.Host {
			fail(w, 403, "access_denied")
			return
		}
	}
	p.mu.Lock()
	a, ok := p.logins[id]
	if ok && equal(cookie.Value, a.CSRF) {
		delete(p.logins, id)
	}
	p.mu.Unlock()
	if !ok || !a.Expires.After(time.Now()) || !equal(cookie.Value, a.CSRF) {
		fail(w, 400, "invalid_request")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "teraland_login_" + id, Path: mustURL(p.config.Issuer).Path + "/login", HttpOnly: true, Secure: !p.config.Development, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	if !equal(r.Form.Get("username"), p.config.Username) || !equal(r.Form.Get("password"), p.config.Password) {
		fail(w, 401, "access_denied")
		return
	}
	code := randomID()
	g := grant{Client: text(a.Claims, "client_id"), Redirect: text(a.Claims, "redirect_uri"), Nonce: text(a.Claims, "nonce"), Scope: text(a.Claims, "scope"), Challenge: text(a.Claims, "code_challenge"), Subject: sha(p.config.Issuer + "\x00" + p.config.Username), AuthTime: time.Now().Unix(), Expires: time.Now().Add(time.Minute)}
	p.mu.Lock()
	if len(p.codes) > 10000 {
		p.mu.Unlock()
		fail(w, 503, "temporarily_unavailable")
		return
	}
	p.codes[code] = g
	p.mu.Unlock()
	p.redirect(w, r, a, object{"code": code})
}
func (p *Provider) redirect(w http.ResponseWriter, r *http.Request, a authRequest, values object) {
	u := mustURL(text(a.Claims, "redirect_uri"))
	q := u.Query()
	for k, v := range values {
		q.Set(k, v.(string))
	}
	q.Set("iss", p.config.Issuer)
	if s := text(a.Claims, "state"); s != "" {
		q.Set("state", s)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}
func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if !form(r) {
		fail(w, 400, "invalid_request")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		fail(w, 400, "unsupported_grant_type")
		return
	}
	id := r.Form.Get("client_id")
	rp, e := p.relyingParty(r.Context(), id)
	if e != nil || !p.authenticate(r, rp, "/token") {
		fail(w, 401, "invalid_client")
		return
	}
	code := r.Form.Get("code")
	p.mu.Lock()
	g, ok := p.codes[code]
	if ok && g.Client == id {
		delete(p.codes, code)
	}
	p.mu.Unlock()
	if !ok || g.Client != id || !g.Expires.After(time.Now()) || g.Redirect != r.Form.Get("redirect_uri") {
		fail(w, 400, "invalid_grant")
		return
	}
	if g.Challenge != "" {
		v := r.Form.Get("code_verifier")
		if len(v) < 43 || len(v) > 128 || !equal(sha(v), g.Challenge) {
			fail(w, 400, "invalid_grant")
			return
		}
		for _, c := range v {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
				fail(w, 400, "invalid_grant")
				return
			}
		}
	}
	now := time.Now().Unix()
	accessToken := randomID()
	digest := sha256.Sum256([]byte(accessToken))
	claims := object{"iss": p.config.Issuer, "sub": g.Subject, "aud": []string{id}, "iat": now, "exp": now + 300, "auth_time": g.AuthTime, "at_hash": base64.RawURLEncoding.EncodeToString(digest[:16])}
	if g.Nonce != "" {
		claims["nonce"] = g.Nonce
	}
	jwt, e := sign(p.signing, "JWT", claims)
	if e != nil {
		fail(w, 500, "server_error")
		return
	}
	p.mu.Lock()
	if len(p.tokens) > 10000 {
		p.mu.Unlock()
		fail(w, 503, "temporarily_unavailable")
		return
	}
	p.tokens[sha(accessToken)] = access{Subject: g.Subject, Expires: time.Now().Add(5 * time.Minute)}
	p.mu.Unlock()
	jsonReply(w, 200, object{"access_token": accessToken, "token_type": "Bearer", "expires_in": 300, "id_token": jwt, "scope": g.Scope})
}
func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	p.mu.Lock()
	a, found := p.tokens[sha(token)]
	p.mu.Unlock()
	if !ok || !strings.EqualFold(scheme, "Bearer") || !found || !a.Expires.After(time.Now()) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		fail(w, 401, "invalid_token")
		return
	}
	jsonReply(w, 200, object{"sub": a.Subject})
}

func requestFailure(w http.ResponseWriter, err error) {
	description := "Request object or federation trust validation failed."
	switch err.Error() {
	case "sub is forbidden in automatic registration request", "client_id / iss mismatch", "missing or expired exp", "invalid audience", "missing or replayed jti", "unregistered redirect URI", "invalid signature":
		description = err.Error()
	}
	jsonReply(w, 400, object{"error": "invalid_request_object", "error_description": description})
}
