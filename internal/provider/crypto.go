package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type object = map[string]any

var algorithms = []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256}

func randomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func text(m object, k string) string  { v, _ := m[k].(string); return v }
func number(m object, k string) int64 { v, _ := m[k].(float64); return int64(v) }
func stringsOf(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		var r []string
		for _, a := range x {
			if s, ok := a.(string); ok {
				r = append(r, s)
			}
		}
		return r
	case string:
		return []string{x}
	}
	return nil
}
func contains(v any, s string) bool {
	for _, x := range stringsOf(v) {
		if x == s {
			return true
		}
	}
	return false
}
func asObject(v any) object { m, _ := v.(map[string]any); return m }
func keySet(v any) (jose.JSONWebKeySet, error) {
	var ks jose.JSONWebKeySet
	b, e := json.Marshal(v)
	if e == nil {
		e = json.Unmarshal(b, &ks)
	}
	if e != nil || len(ks.Keys) == 0 {
		return ks, errors.New("missing public keys")
	}
	for _, k := range ks.Keys {
		if !k.Valid() || !k.IsPublic() {
			return ks, errors.New("invalid or private public key")
		}
		if r, ok := k.Key.(*rsa.PublicKey); ok && r.N.BitLen() < 2048 {
			return ks, errors.New("RSA key too small")
		}
	}
	return ks, nil
}
func publicSet(k jose.JSONWebKey) jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{k.Public()}}
}
func sign(k jose.JSONWebKey, typ string, m object) (string, error) {
	s, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if e != nil {
		return "", e
	}
	b, e := json.Marshal(m)
	if e != nil {
		return "", e
	}
	j, e := s.Sign(b)
	if e != nil {
		return "", e
	}
	return j.CompactSerialize()
}
func parse(token string) (*jose.JSONWebSignature, object, error) {
	j, e := jose.ParseSigned(token, algorithms)
	if e != nil {
		return nil, nil, e
	}
	if len(j.Signatures) != 1 {
		return nil, nil, errors.New("one signature required")
	}
	var m object
	e = json.Unmarshal(j.UnsafePayloadWithoutVerification(), &m)
	if e != nil || m == nil {
		return nil, nil, errors.New("invalid JWT claims")
	}
	return j, m, nil
}
func verify(token string, ks jose.JSONWebKeySet, typ string) (object, error) {
	j, _, e := parse(token)
	if e != nil {
		return nil, e
	}
	h := j.Signatures[0].Header
	if typ != "" && fmt.Sprint(h.ExtraHeaders[jose.HeaderKey("typ")]) != typ {
		return nil, errors.New("invalid JWT type")
	}
	for _, k := range ks.Keys {
		if h.KeyID != "" && h.KeyID != k.KeyID {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != h.Algorithm {
			continue
		}
		b, e := j.Verify(k.Key)
		if e == nil {
			var m object
			e = json.Unmarshal(b, &m)
			return m, e
		}
	}
	return nil, errors.New("invalid signature")
}
func validTimes(m object, requireIat bool) error {
	now := time.Now().Unix()
	exp := number(m, "exp")
	if exp <= now {
		return errors.New("missing or expired exp")
	}
	if requireIat && (number(m, "iat") == 0 || number(m, "iat") > now+30 || number(m, "iat") >= exp) {
		return errors.New("invalid iat")
	}
	if number(m, "nbf") > now+30 {
		return errors.New("JWT not yet valid")
	}
	return nil
}
func loadKey(path string, use string) (jose.JSONWebKey, error) {
	b, e := os.ReadFile(path)
	if e == nil {
		var k jose.JSONWebKey
		e = json.Unmarshal(b, &k)
		if e != nil || !k.Valid() || k.IsPublic() {
			return k, errors.New("invalid private key file")
		}
		return k, nil
	}
	if !os.IsNotExist(e) {
		return jose.JSONWebKey{}, e
	}
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return jose.JSONWebKey{}, e
	}
	j := jose.JSONWebKey{Key: k, KeyID: randomID(), Algorithm: "RS256", Use: use}
	if use == "enc" {
		j.Algorithm = ""
	}
	b, e = json.Marshal(j)
	if e != nil {
		return j, e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return j, e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return j, e
	}
	_, e = f.Write(b)
	ce := f.Close()
	if e == nil {
		e = ce
	}
	return j, e
}
func sha(s string) string {
	b := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func decrypt(token string, k jose.JSONWebKey) (string, error) {
	if strings.Count(token, ".") != 4 {
		return token, nil
	}
	j, e := jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.RSA_OAEP}, []jose.ContentEncryption{jose.A256GCM})
	if e != nil {
		return "", e
	}
	if j.Header.ExtraHeaders[jose.HeaderKey("cty")] != "JWT" {
		return "", errors.New("nested JWT required")
	}
	b, e := j.Decrypt(k.Key)
	return string(b), e
}
