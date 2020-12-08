package gojwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// IANA registered claims
const (
	ExpiryClaim    = "exp"
	NotBeforeClaim = "nbf"
	IssuedAtClaim  = "iat"
)

type JWT struct {
	Claims
	h   *Header
	raw string
}

// Token parses a JSON-Web-Token into a JWT object. An
// error is returned if the token is not valid.
func Token(token string) (*JWT, error) {
	if token == "" {
		return nil, errors.New("token is empty")
	}

	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		return nil, errors.New("invalid token structure")
	}

	jwt := &JWT{
		Claims: make(Claims),
		h:      &Header{},
		raw:    token,
	}

	err := unmarshalFromBase64JSON(tokenParts[0], jwt.h)
	if err != nil {
		return nil, fmt.Errorf("header: %v", err)
	}

	err = unmarshalFromBase64JSON(tokenParts[1], &jwt.Claims)
	if err != nil {
		return nil, fmt.Errorf("payload: %v", err)
	}

	return jwt, nil
}

func unmarshalFromBase64JSON(data string, v interface{}) error {
	bytes, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return errors.New("invalid base64")
	}

	err = json.Unmarshal(bytes, v)
	if err != nil {
		return errors.New("invalid json")
	}

	return nil
}

// Verify validates the JSON-Web-Token's signature against
// the rest of the token. An error is returned if the token
// is invalid, not yet valid, expired, or if the alg Verify()
// function returns an error.
func (jwt *JWT) Verify(alg Algorithm) error {
	if jwt.h.Alg != alg.Name() {
		return errors.New("algorithm mismatch")
	}

	ld := strings.LastIndex(jwt.raw, ".")
	token := []byte(jwt.raw[:ld])
	encSignature := []byte(jwt.raw[ld+1:])
	signature := make([]byte, base64.RawURLEncoding.DecodedLen(len(encSignature)))
	n, _ := base64.RawURLEncoding.Decode(signature, encSignature)

	valid := alg.Verify(token, signature[:n])
	if !valid {
		return errors.New("token is not valid")
	}

	now := time.Now().UTC().Unix()
	nbf, nbfOk := jwt.NotBefore()
	if nbfOk && nbf.Unix() > now {
		return errors.New("token is not yet valid")
	}

	exp, expOk := jwt.Expiry()
	if expOk && exp.Unix() <= now {
		return errors.New("token has expired")
	}

	return nil
}

// Header represents the header of a JSON-Web-Token, which
// contains metadata related to the token.
type Header struct {
	// Type defines the type of JSON-Web-Token the header belongs to.
	// This field is recommended to be set, and equal to "JWT",
	// according to the RFC 7519 (https://tools.ietf.org/html/rfc7519) specification.
	Type string `json:"typ"`

	// Alg defines the type of signing algorithm used to sign
	// a token. This isn't required, but allows a verifying
	// service to determine which algorithm was used to sign the token.
	Alg string `json:"alg"`
}

// Claims represents a JSON-Web-Token payload,
// in the form of a map[string]interface{}
type Claims map[string]interface{}

// String returns a claim with the given key. If the claim
// exists, the value is returned alongside true. If either
// the value does not exist, or is not a string, a default
// string, "", and false will be returned.
func (c Claims) String(key string) (string, bool) {
	v, ok := c[key]
	if !ok {
		return "", false
	}

	s, ok := v.(string)
	if !ok {
		return "", false
	}

	return s, true
}

// Int returns a claim with the given key. If the claim
// exists, the value is returned alongside true. If either
// the value does not exist, or is not a float64 or int, a
// default int value, 0, and false will be returned.
func (c Claims) Int(key string) (int, bool) {
	v, ok := c[key]
	if !ok {
		return 0, false
	}

	f, ok := v.(float64)
	if !ok {
		return 0, false
	}

	return int(f), true
}

// Time returns a claim with the given key, as a time.Time.
// Time assumes the claim value is a Unix timestamp, stored
// as a float64. If the value exists and is a time, it will
// be returned alongside true, otherwise a default time and false.
func (c Claims) Time(key string) (time.Time, bool) {
	v, ok := c[key]
	if !ok {
		return time.Time{}, false
	}

	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}

	return time.Unix(0, int64(f*float64(time.Second))), true
}

// Expiry returns the value of the "exp" claim, as a time.Time.
// If this value does not exist or is not a time, a default value
// will be returned, as well as false.
func (c Claims) Expiry() (time.Time, bool) {
	return c.Time(ExpiryClaim)
}

// NotBefore returns the value of the "nbf" claim, as a time.Time.
// If this value does not exist or is not a time, a default value
// will be returned, as well as false.
func (c Claims) NotBefore() (time.Time, bool) {
	return c.Time(NotBeforeClaim)
}

// IssuedAt returns the value of the "iat" claim, as a time.Time.
// If this value does not exist or is not a time, a default value
// will be returned, as well as false.
func (c Claims) IssuedAt() (time.Time, bool) {
	return c.Time(IssuedAtClaim)
}
