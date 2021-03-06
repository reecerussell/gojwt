package rsa_test

import (
	"crypto"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/reecerussell/gojwt"
	"github.com/reecerussell/gojwt/rsa"
)

const testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAykIPjn9PKaAfE22L7PJM3EkwaZbDwzXhdu7oHJ8vg03Pwf/b
yJKAZT5qRD4p/z836gaZMZpA/pOoOjTQMLEGwKGFG9SBsP99ocMUSIrdM1s+D+Ew
rk7sDRCGEJWrr8rT+iZTwuUexTq6HXJHVM8XaOFnN37OB9DhuG7jFVUPQyDlVNSX
8VZxajD8GdhuPpzpQfFIGFktfOyHPn5QYUsuCWbLa0k7Xx7e1e/J7PUDrLh8cI3l
Dt9Ti/pBG+O2oVl7ma6mmKWCCfpbNKeSRdPeMaA8goKwFAfm832luVD1HBIh3imW
vay+KigYOB6p22BhXnhJW6Rxvo7eYnX8WBhq3wIDAQABAoIBAD26v8i77ktEBXgG
fShKI08wP0harVDNBw0niUwDAZtPilMpZcjnfaxoykIdvu+aOdSBQwwyiheotTVe
nRPfU7JDGb8Osq50q8FNKsmhKDXeaSirkBIDIGQ0YNZ697VlcCDuxa28BBIqBFes
YzztH7Xw5XG4j+UuyVVi8oe2ODxCKH5TwSaEkgV6JBWiJlL9rIO8j223lKUhIVgY
SwE1l++Vr8bIlvVRi7H+5Oy7Y3DfnkPZ8Ic7LBs6BgvFXe6Lr0gBQP8PrhezI+vx
IVctrTRuMEKnIOCbKeRJvNrhiI+vix4kfM1/op8nSJvqnJlRdWji1W14uxTaUmHj
Mpok5FECgYEA+ZNHebbWWNrWE+fHYwZhuq713t7ymn4PNHLzNpfGOyHuVwTtO7li
zo5uS1A1l3glBx32zLwZFWgRXOLRdNtihwpgqM0pxjCiuZbHSxsqG8UqL9ZVXl5U
dEAzq5ChJR97H3nxufd7YTBIoWvHT7MmoZwP7qWUWwax/kmnb8XKO5UCgYEAz3b1
Ble166LID2NdP3mbaLamsbZuZwKUPJYgS0yLg0I34WnPckYfKfWcsWB2NjeOrr6V
TF+gzVpUBq4CCC4gJNCfWlNYjFKOVn/9i4iRLldTThAxrT/mqYLwrb4eoYMALc8K
mBIig9/DxUpKZK23Ks2xZ8meBPwJUoPIrlfLz6MCgYEAuXEt0sqASlWQbAn0pSfA
xi3qk0eljBXOxnIDNbVgnd+AcTg/7fi56jD60wsuRvYGzVr+XvIE0VsaS6JdcC7y
7tRPLh4DxDevMadPPgdZKnk9932SwSPmLNrnibtVgXf6zFCXxE6XZoex7/9dgWLk
eYC0deaibWB0MTYZK3wT4GECgYANMosJuUCoWbWSTQbch9bcBWp7OZiyUtatN/ub
7qWdVvQJEdsRcOaAm9A49GLwtf4MnbEPp7Gp/ooD1sPoU07WKLNKYqzqWEIXvJKb
creRlBqHh74xQDRjKiI3WzXFnni/cUFCRT0O2Igyn7Q1zVsujOExMgEsXgAV0K5O
cOVVMwKBgQDqyYwrQnmt68HbLL6RkoYpPRMevu1+R4cLyEZEv/y8qZzBYVnt9iNz
DPyPaqEGQ5vCuykJb3HT7rp+Nv/DJReD9lMGpZp2/MmEuDnUt1kLqstgX08Lox3O
H9MfLqzcWxf/sUxcK+KZ6PYE42q/6HkbIrSehbpJoFMnQND+uZAv3w==
-----END RSA PRIVATE KEY-----
`

const testPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAykIPjn9PKaAfE22L7PJM
3EkwaZbDwzXhdu7oHJ8vg03Pwf/byJKAZT5qRD4p/z836gaZMZpA/pOoOjTQMLEG
wKGFG9SBsP99ocMUSIrdM1s+D+Ewrk7sDRCGEJWrr8rT+iZTwuUexTq6HXJHVM8X
aOFnN37OB9DhuG7jFVUPQyDlVNSX8VZxajD8GdhuPpzpQfFIGFktfOyHPn5QYUsu
CWbLa0k7Xx7e1e/J7PUDrLh8cI3lDt9Ti/pBG+O2oVl7ma6mmKWCCfpbNKeSRdPe
MaA8goKwFAfm832luVD1HBIh3imWvay+KigYOB6p22BhXnhJW6Rxvo7eYnX8WBhq
3wIDAQAB
-----END PUBLIC KEY-----
`

func TestNew(t *testing.T) {
	alg, err := rsa.New([]byte(testPrivateKey), crypto.SHA256)
	assert.Nil(t, err)
	assert.NotNil(t, alg)
}

func TestNew_GivenPublicKey_ReturnsNoError(t *testing.T) {
	alg, err := rsa.New([]byte(testPublicKey), crypto.SHA256)
	assert.Nil(t, err)
	assert.NotNil(t, alg)
}

func TestNew_GivenInvalidPem_ReturnsError(t *testing.T) {
	const defoNotPem string = "7238yshiweidlkdsfkbds"

	rsa, err := rsa.New([]byte(defoNotPem), crypto.SHA256)
	assert.Nil(t, rsa)
	assert.Equal(t, "invalid key format", err.Error())
}

func TestNew_GivenInvalidPKCS1PrivateKey_ReturnsError(t *testing.T) {
	invalidKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAykIPjn9PKaAfE22L7PJM3EkwaZbDwzXhdu7oHJ8vg03Pwf/b
yJKAZT5qRD4p/z836gaZMZpA/pOoOjTQMLEGwKGFG9SBsP99ocMUSIrdM1s+D+Ew
rk7sDRCGEJWrr8rT+iZTwuUexTq6HXJHVM8XaOFnN37OB9DhuG7jFVUPQyDlVNSX
8VZxajD8GdhuPpzpQfFIGFktfOyHPn5QYUsuCWbLa0k7Xx7e1e/J7PUDrLh8cI3l
Dt9Ti/pBG+O2oVl7ma6mmKWCCfpbNKeSRdPeMaA8goKwFAfm832luVD1HBIh3imW
vay+KigYOB6p22BhXnhJW6Rxvo7eYnX8WBhq3wIDAQABAoIBAD26v8i77ktEBXgG
fShKI08wP0harVDNBw0niUwDAZtPilMpZcjnfaxoykIdvu+aOdSBQwwyiheotTVe
nRPfU7JDGb8Osq50q8FNKsmhKDXeaSirkBIDIGQ0YNZ697VlcCDuxa28BBIqBFes
YzztH7Xw5XG4j+UuyVVi8oe2ODxCKH5TwSaEkgV6JBWiJlL9rIO8j223lKUhIVgY
SwE1l++Vr8bIlvVRi7H+5Oy7Y3DfnkPZ8Ic7LBs6BgvFXe6Lr0gBQP8PrhezI+vx
creRlBqHh74xQDRjKiI3WzXFnni/cUFCRT0O2Igyn7Q1zVsujOExMgEsXgAV0K5O
cOVVMwKBgQDqyYwrQnmt68HbLL6RkoYpPRMevu1+R4cLyEZEv/y8qZzBYVnt9iNz
DPyPaqEGQ5vCuykJb3HT7rp+Nv/DJReD9lMGpZp2/MmEuDnUt1kLqstgX08Lox3O
H9MfLqzcWxf/sUxcK+KZ6PYE42q/6HkbIrSehbpJoFMnQND+uZAv3w==
-----END RSA PRIVATE KEY-----
`)

	rsa, err := rsa.New(invalidKey, crypto.SHA256)
	assert.Nil(t, rsa)
	assert.NotNil(t, err)
}

func TestNewFromFile(t *testing.T) {
	file, err := os.Create("my_super_secret_test_key.pem")
	if err != nil {
		panic(err)
	}

	file.Write([]byte(testPrivateKey))
	file.Close()

	t.Cleanup(func() {
		os.Remove("my_super_secret_test_key.pem")
	})

	alg, err := rsa.NewFromFile("my_super_secret_test_key.pem", crypto.SHA256)
	assert.Nil(t, err)
	assert.NotNil(t, alg)
}

func TestNewFromFile_GivenNonExistantFilename_ReturnsError(t *testing.T) {
	alg, err := rsa.NewFromFile("my_super_secret_test_key_2.pem", crypto.SHA256)
	assert.Nil(t, alg)
	assert.True(t, os.IsNotExist(err))
}

func TestSign(t *testing.T) {
	alg, err := rsa.New([]byte(testPrivateKey), crypto.SHA256)
	if err != nil {
		panic(err)
	}

	bytes, _ := alg.Sign([]byte("Hello World"))
	assert.NotNil(t, bytes)
}

func TestSign_WithNoPrivateKey_Panics(t *testing.T) {
	alg, err := rsa.New([]byte(testPublicKey), crypto.SHA256)
	if err != nil {
		panic(err)
	}

	defer func() {
		r := recover()
		assert.NotNil(t, r)
	}()

	bytes, _ := alg.Sign([]byte("Hello World"))
	assert.Nil(t, bytes)
}

func TestVerify_GivenPrivateKey_ReturnsNoError(t *testing.T) {
	const base64Signature string = "xncU8W6S3AfWvr9gmAYOK0yrL3NDVmubUMMZkzXBtoBbxe/RTrcQJX1Zq9e5mWEDB/lJt0oMLyCvbNKMx83ev2HATcKa40CTTzrsVatFaP4EUnKnuO4ugNRJQozIQPDN6qUcVbWwW9SSfvHoroeEllr30yOUDfmjz1+smUJfwancGPZBDgvkz5IJVfkKo5g8TDpS6T9vPwjN8ZSk+c6fmlXehtqwxRpec/V8bVXXKn8HeCI/1fgi3vG5tAswRaOXYwCtXPgcrNLJXxUTfLXO58iEz2sh+qRWBIC6nDZSBdkPKY3r/RRvplReoFY8IElWsd2dmwEqYMxhw1mEho/8iA"
	signature, _ := base64.RawStdEncoding.DecodeString(base64Signature)

	alg, err := rsa.New([]byte(testPrivateKey), crypto.SHA256)
	if err != nil {
		panic(err)
	}

	valid, _ := alg.Verify([]byte("Hello World"), signature)
	assert.True(t, valid)
}

func TestVerify_GivenPublicKey_ReturnsNoError(t *testing.T) {
	const base64Signature string = "xncU8W6S3AfWvr9gmAYOK0yrL3NDVmubUMMZkzXBtoBbxe/RTrcQJX1Zq9e5mWEDB/lJt0oMLyCvbNKMx83ev2HATcKa40CTTzrsVatFaP4EUnKnuO4ugNRJQozIQPDN6qUcVbWwW9SSfvHoroeEllr30yOUDfmjz1+smUJfwancGPZBDgvkz5IJVfkKo5g8TDpS6T9vPwjN8ZSk+c6fmlXehtqwxRpec/V8bVXXKn8HeCI/1fgi3vG5tAswRaOXYwCtXPgcrNLJXxUTfLXO58iEz2sh+qRWBIC6nDZSBdkPKY3r/RRvplReoFY8IElWsd2dmwEqYMxhw1mEho/8iA"
	signature, _ := base64.RawStdEncoding.DecodeString(base64Signature)

	alg, err := rsa.New([]byte(testPublicKey), crypto.SHA256)
	if err != nil {
		panic(err)
	}

	valid, _ := alg.Verify([]byte("Hello World"), signature)
	assert.True(t, valid)
}

func TestVerify_GivenInvalidSignature_ReturnsFalse(t *testing.T) {
	alg, err := rsa.New([]byte(testPrivateKey), crypto.SHA256)
	if err != nil {
		panic(err)
	}

	signature := []byte("my invalid signature")
	valid, _ := alg.Verify([]byte("Hello World"), signature)
	assert.False(t, valid)
}

func TestName_WithPrivateKey_ReturnsCorrectName(t *testing.T) {
	alg, err := rsa.New([]byte(testPrivateKey), crypto.SHA256)
	if err != nil {
		panic(err)
	}

	name, err := alg.Name()
	assert.NoError(t, err)
	assert.Equal(t, "RS256", name)
}

func TestName_WithPublicKey_ReturnsCorrectName(t *testing.T) {
	alg, err := rsa.New([]byte(testPublicKey), crypto.SHA256)
	if err != nil {
		panic(err)
	}

	name, err := alg.Name()
	assert.NoError(t, err)
	assert.Equal(t, "RS256", name)
}

func TestSize(t *testing.T) {
	alg, err := rsa.New([]byte(testPrivateKey), crypto.SHA256)
	if err != nil {
		panic(err)
	}

	size, err := alg.Size()
	assert.NoError(t, err)
	assert.Equal(t, 256, size)
}

func TestE2E(t *testing.T) {
	alg, err := rsa.New([]byte(testPrivateKey), crypto.SHA256)
	assert.Nil(t, err)

	// Creating a new builder object, then adding some claims.
	builder, err := gojwt.New(alg)
	assert.NoError(t, err)

	builder.AddClaim("name", "John Doe").
		SetExpiry(time.Now().Add(1 * time.Hour))

	// Finally, building the token.
	token, err := builder.Build()
	if err != nil {
		panic(err)
	}

	jwt, err := gojwt.Token(token)
	assert.Nil(t, err)

	err = jwt.Verify(alg)
	assert.Nil(t, err)
}
