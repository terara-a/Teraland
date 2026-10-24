package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	jose "github.com/go-jose/go-jose/v4"
	"net/http"
	"net/url"
	"time"
)

func (p *Provider) entityConfiguration(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Unix()
	claims := object{"iss": p.config.Issuer, "sub": p.config.Issuer, "iat": now, "exp": now + 3600, "jwks": publicSet(p.signing), "metadata": object{"openid_provider": p.Metadata()}}
	if len(p.config.AuthorityHints) > 0 {
		claims["authority_hints"] = p.config.AuthorityHints
	}
	token, e := sign(p.signing, "entity-statement+jwt", claims)
	if e != nil {
		fail(w, 500, "server_error")
		return
	}
	w.Header().Set("Content-Type", "application/entity-statement+jwt")
	_, _ = w.Write([]byte(token))
}
func validateEntity(raw, id string) (object, error) {
	_, m, e := parse(raw)
	if e != nil {
		return nil, e
	}
	keys, e := keySet(m["jwks"])
	if e != nil {
		return nil, e
	}
	m, e = verify(raw, keys, "entity-statement+jwt")
	if e != nil {
		return nil, e
	}
	if text(m, "iss") != id || text(m, "sub") != id {
		return nil, errors.New("entity identifier mismatch")
	}
	if e = validTimes(m, true); e != nil {
		return nil, e
	}
	if e = unsupported(m); e != nil {
		return nil, e
	}
	return m, nil
}
func unsupported(m object) error {
	// Reject unsupported trust restrictions rather than silently ignoring them.
	for _, k := range []string{"crit", "policy_language_crit", "constraints", "metadata_policy", "trust_mark_issuers", "trust_mark_owners"} {
		if v, ok := m[k]; ok && v != nil {
			return errors.New("unsupported federation restriction: " + k)
		}
	}
	return nil
}
func (p *Provider) entity(ctx context.Context, id string) (string, object, error) {
	b, e := p.fetch(ctx, id+"/.well-known/openid-federation")
	if e != nil {
		return "", nil, e
	}
	m, e := validateEntity(string(b), id)
	return string(b), m, e
}

// resolve builds and verifies upward to a locally pinned trust anchor. Each
// subordinate statement binds the child ID and its exact federation keys.
func (p *Provider) resolve(ctx context.Context, id string, seen map[string]bool, depth int) (object, error) {
	if depth > 5 || seen[id] {
		return nil, errors.New("trust chain depth or cycle")
	}
	seen[id] = true
	defer delete(seen, id)
	raw, leaf, e := p.entity(ctx, id)
	if e != nil {
		return nil, e
	}
	if keys, ok := p.config.TrustAnchors[id]; ok {
		if _, e = verify(raw, keys, "entity-statement+jwt"); e != nil {
			return nil, e
		}
		return leaf, nil
	}
	hints := stringsOf(leaf["authority_hints"])
	if len(hints) > 8 {
		return nil, errors.New("too many authority hints")
	}
	for _, parent := range hints {
		superior, e := p.resolve(ctx, parent, seen, depth+1)
		if e != nil {
			continue
		}
		fed := asObject(asObject(superior["metadata"])["federation_entity"])
		endpoint := text(fed, "federation_fetch_endpoint")
		if endpoint == "" {
			continue
		}
		u, e := url.Parse(endpoint)
		if e != nil {
			continue
		}
		q := u.Query()
		q.Set("sub", id)
		q.Set("iss", parent)
		u.RawQuery = q.Encode()
		b, e := p.fetch(ctx, u.String())
		if e != nil {
			continue
		}
		keys, e := keySet(superior["jwks"])
		if e != nil {
			continue
		}
		statement, e := verify(string(b), keys, "entity-statement+jwt")
		if e != nil || text(statement, "iss") != parent || text(statement, "sub") != id || validTimes(statement, true) != nil || unsupported(statement) != nil {
			continue
		}
		childKeys, e := keySet(statement["jwks"])
		if e != nil {
			continue
		}
		if _, e = verify(raw, childKeys, "entity-statement+jwt"); e != nil {
			continue
		}
		if number(statement, "exp") < number(leaf, "exp") {
			leaf["exp"] = statement["exp"]
		}
		if number(superior, "exp") < number(leaf, "exp") {
			leaf["exp"] = superior["exp"]
		}
		// Metadata supplied by a verified superior takes precedence.
		if sm := asObject(statement["metadata"]); sm != nil {
			lm := asObject(leaf["metadata"])
			if lm == nil {
				lm = object{}
				leaf["metadata"] = lm
			}
			for typ, v := range sm {
				target := asObject(lm[typ])
				if target == nil {
					target = object{}
					lm[typ] = target
				}
				for k, x := range asObject(v) {
					target[k] = x
				}
			}
		}
		return leaf, nil
	}
	return nil, errors.New("no valid path to a pinned trust anchor")
}
func (p *Provider) relyingParty(ctx context.Context, id string) (object, error) {
	entity, e := p.resolve(ctx, id, map[string]bool{}, 0)
	if e != nil {
		return nil, e
	}
	rp := asObject(asObject(entity["metadata"])["openid_relying_party"])
	if rp == nil || !contains(rp["client_registration_types"], "automatic") {
		return nil, errors.New("automatic RP registration required")
	}
	if len(stringsOf(rp["redirect_uris"])) == 0 {
		return nil, errors.New("missing redirect URIs")
	}
	for _, uri := range stringsOf(rp["redirect_uris"]) {
		u, e := url.Parse(uri)
		if e != nil || u.Host == "" || u.Fragment != "" || u.User != nil || (u.Scheme != "https" && !(p.config.Development && u.Scheme == "http")) {
			return nil, errors.New("invalid registered redirect URI")
		}
	}
	if method := text(rp, "token_endpoint_auth_method"); method != "" && method != "private_key_jwt" {
		return nil, errors.New("private_key_jwt required")
	}
	if rp["jwks"] != nil && rp["jwks_uri"] != nil {
		return nil, errors.New("ambiguous RP keys")
	}
	if rp["jwks"] == nil {
		b, e := p.fetch(ctx, text(rp, "jwks_uri"))
		if e != nil {
			return nil, e
		}
		var ks object
		if e = json.Unmarshal(b, &ks); e != nil {
			return nil, e
		}
		rp["jwks"] = ks
	}
	if _, e = keySet(rp["jwks"]); e != nil {
		return nil, e
	}
	rp["client_id"] = id
	rp["trust_exp"] = entity["exp"]
	return rp, nil
}
func (p *Provider) requestObject(ctx context.Context, raw, clientID string) (authRequest, error) {
	raw, e := decrypt(raw, p.encryption)
	if e != nil {
		return authRequest{}, e
	}
	jws, claims, e := parse(raw)
	if e != nil {
		return authRequest{}, e
	}
	typ := fmt.Sprint(jws.Signatures[0].Header.ExtraHeaders[jose.HeaderKey("typ")])
	if typ != "JWT" && typ != "oauth-authz-req+jwt" {
		return authRequest{}, errors.New("invalid request object type")
	}
	if clientID == "" || text(claims, "client_id") != clientID || text(claims, "iss") != clientID {
		return authRequest{}, errors.New("client_id / iss mismatch")
	}
	rp, e := p.relyingParty(ctx, clientID)
	if e != nil {
		return authRequest{}, e
	}
	keys, e := keySet(rp["jwks"])
	if e != nil {
		return authRequest{}, e
	}
	claims, e = verify(raw, keys, "")
	if e != nil {
		return authRequest{}, e
	}
	if e = validTimes(claims, false); e != nil {
		return authRequest{}, e
	}
	if number(claims, "exp") > time.Now().Add(10*time.Minute).Unix() {
		return authRequest{}, errors.New("request exp too far in future")
	}
	if _, ok := claims["sub"]; ok {
		return authRequest{}, errors.New("sub is forbidden in automatic registration request")
	}
	aud := stringsOf(claims["aud"])
	if len(aud) != 1 || aud[0] != p.config.Issuer {
		return authRequest{}, errors.New("invalid audience")
	}
	if !contains(rp["redirect_uris"], text(claims, "redirect_uri")) {
		return authRequest{}, errors.New("unregistered redirect URI")
	}
	if text(claims, "response_type") != "code" {
		return authRequest{}, errors.New("only authorization code supported")
	}
	scope := text(claims, "scope")
	if !contains(splitScope(scope), "openid") {
		return authRequest{}, errors.New("openid scope required")
	}
	for _, s := range stringsOf(splitScope(scope)) {
		if s != "openid" && s != "profile" {
			return authRequest{}, errors.New("unsupported scope")
		}
	}
	if mode := text(claims, "response_mode"); mode != "" && mode != "query" {
		return authRequest{}, errors.New("unsupported response mode")
	}
	if challenge := text(claims, "code_challenge"); challenge != "" {
		if text(claims, "code_challenge_method") != "S256" || len(challenge) != 43 {
			return authRequest{}, errors.New("S256 PKCE required")
		}
	} else if text(claims, "code_challenge_method") != "" {
		return authRequest{}, errors.New("missing PKCE challenge")
	}
	if !p.remember("request", clientID, text(claims, "jti"), number(claims, "exp")) {
		return authRequest{}, errors.New("missing or replayed jti")
	}
	exp := number(claims, "exp")
	if number(rp, "trust_exp") < exp {
		exp = number(rp, "trust_exp")
	}
	return authRequest{Claims: claims, Client: rp, Expires: time.Unix(exp, 0)}, nil
}
