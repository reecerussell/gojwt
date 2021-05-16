package gojwt

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// Builder is a type of object used to build a JWT token.
type Builder struct {
	alg    Algorithm
	header *Header
	claims Claims
}

// New returns a new instance of Builder, configured
// to use the algorithm alg.
func New(alg Algorithm) (*Builder, error) {
	name, err := alg.Name()
	if err != nil {
		return nil, err
	}

	return &Builder{
		alg: alg,
		header: &Header{
			Type: "JWT",
			Alg:  name,
		},
		claims: make(Claims),
	}, nil
}

// AddClaim adds a claim to the builder, which will be
// placed inside of the JWT payload. If a claim with the given
// name already exists, it will be overridden.
func (b *Builder) AddClaim(name string, v interface{}) *Builder {
	b.claims[name] = v

	return b
}

// AddClaims adds a range of claims to the builder, which will be
// placed inside of the JWT payload. If a claim with the given
// name already exists, it will be overridden.
//
// AddClaims loops through the given claims, then calls AddClaim.
func (b *Builder) AddClaims(claims Claims) *Builder {
	for name, value := range claims {
		b.AddClaim(name, value)
	}

	return b
}

// SetExpiry is a helper function to set the "exp" claim
// of the token. Given a time, the "exp" claim will be set
// to the unix timestamp of the given time.
func (b *Builder) SetExpiry(t time.Time) *Builder {
	b.AddClaim(ExpiryClaim, convertTimeToTimestamp(t))

	return b
}

// SetNotBefore is a helper function to set the "nbf" claim
// of the token. Given a time, the "nbf" claim will be set
// to the unix timestamp of the given time.
func (b *Builder) SetNotBefore(t time.Time) *Builder {
	b.AddClaim(NotBeforeClaim, convertTimeToTimestamp(t))

	return b
}

// SetIssuedAt is a helper function to set the "iat" claim
// of the token. Given a time, the "iat" claim will be set
// to the unix timestamp of the given time.
func (b *Builder) SetIssuedAt(t time.Time) *Builder {
	b.AddClaim(IssuedAtClaim, convertTimeToTimestamp(t))

	return b
}

func convertTimeToTimestamp(t time.Time) float64 {
	return float64(t.UnixNano() / 1e9)
}

// Build builds the JWT by encoding the header and claims, then
// signing them using the configured algorithm.
//
// An error is returned if the algorithms Sign() func returns an error.
func (b *Builder) Build() (string, error) {
	headerBytes := marshalToBase64JSON(b.header)
	claimBytes := marshalToBase64JSON(b.claims)

	l := len(headerBytes) + 1 + len(claimBytes)

	sigLen, err := b.alg.Size()
	if err != nil {
		return "", err
	}

	token := make([]byte, l, l+1+base64.RawURLEncoding.EncodedLen(sigLen))
	i := copy(token, headerBytes)
	token[i] = byte('.')
	i++
	i += copy(token[i:], claimBytes)

	sig, err := b.alg.Sign(token)
	if err != nil {
		return "", err
	}

	token = token[:cap(token)]
	token[i] = byte('.')
	i++
	copy(token[i:], convertToBase64(sig))

	return string(token), nil
}

// Marshals v, then converts the JSON to URl-safe base64.
func marshalToBase64JSON(v interface{}) []byte {
	bytes, _ := json.Marshal(v)
	return convertToBase64(bytes)
}

// Converts a byte slice to URL-safe base64.
func convertToBase64(data []byte) []byte {
	n := base64.RawURLEncoding.EncodedLen(len(data))
	buf := make([]byte, n)
	base64.RawURLEncoding.Encode(buf, data)
	return buf
}
