package kms

import (
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/assert"

	"github.com/reecerussell/gojwt"
)

// A test key in AWS KMS
var testKeyId = os.Getenv("KMS_KEY_ID")

func TestNew_GivenUnsupportedAlgorithm_ReturnsError(t *testing.T) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	s, err := New(sess, testKeyId, "3irwkhef")
	assert.Nil(t, s)
	assert.NotNil(t, err)
}

func TestNew_GivenNilSession_ReturnsError(t *testing.T) {
	s, err := New(nil, testKeyId, RSA_PKCS1_S256)
	assert.Nil(t, s)
	assert.NotNil(t, err)
}

func TestName(t *testing.T) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	s, err := New(sess, testKeyId, RSA_PKCS1_S256)
	assert.NoError(t, err)

	name, err := s.Name()
	assert.NoError(t, err)
	assert.Equal(t, "RS256", name)
}

func TestSign(t *testing.T) {
	const base64Signature string = "rqlaN2siwvowvNTx2YcX+dtfQeNUn5iKxQN3zglTjHnexqCYIzhJDDQ9Dy6U1C6o4DX2fRJlhm9cEjrDZrr/VdTtdCLDsOcxmkBHHwqGsXn70TOvrKdv5boLwqU3ICvJvIIzlDiBSf/ESkJD2HUljMa8xrzPDKkvjqfXDcxVnOxrlgWTJ9BCHxn649bNMceSdK1OUdNb1LKTWnF+8G1PsGclQ1MLxqxVWJLR7/Dlgw3TXY+6IBrVqrnFCz7bPbA9L4lGADU6UsNcdqyn+XBblY5fE4uYe6xGwLisx0ikIBtt307b2aftukcfnwhBm8pQ/nvUm8hdRCJ/n0Plf4EEow"
	expectedSignature, _ := base64.RawStdEncoding.DecodeString(base64Signature)

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	s, err := New(sess, testKeyId, RSA_PKCS1_S256)
	assert.NoError(t, err)

	data := []byte("Hello World")
	signature, err := s.Sign(data)
	assert.NoError(t, err)
	assert.Equal(t, expectedSignature, signature)
}

func TestSign_GivenInvalidKeyId_ReturnsError(t *testing.T) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	s, err := New(sess, "not a key id", RSA_PKCS1_S256)
	assert.NoError(t, err)

	signature, err := s.Sign([]byte("Hello World"))
	assert.Nil(t, signature)
	assert.NotNil(t, err)
}

func TestVerify(t *testing.T) {
	const base64Signature string = "rqlaN2siwvowvNTx2YcX+dtfQeNUn5iKxQN3zglTjHnexqCYIzhJDDQ9Dy6U1C6o4DX2fRJlhm9cEjrDZrr/VdTtdCLDsOcxmkBHHwqGsXn70TOvrKdv5boLwqU3ICvJvIIzlDiBSf/ESkJD2HUljMa8xrzPDKkvjqfXDcxVnOxrlgWTJ9BCHxn649bNMceSdK1OUdNb1LKTWnF+8G1PsGclQ1MLxqxVWJLR7/Dlgw3TXY+6IBrVqrnFCz7bPbA9L4lGADU6UsNcdqyn+XBblY5fE4uYe6xGwLisx0ikIBtt307b2aftukcfnwhBm8pQ/nvUm8hdRCJ/n0Plf4EEow"
	signature, _ := base64.RawStdEncoding.DecodeString(base64Signature)

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	s, err := New(sess, testKeyId, RSA_PKCS1_S256)
	assert.NoError(t, err)

	data := []byte("Hello World")
	ok, err := s.Verify(data, signature)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestVerify_GivenInvalidKeyId_ReturnsError(t *testing.T) {
	const base64Signature string = "rqlaN2siwvowvNTx2YcX+dtfQeNUn5iKxQN3zglTjHnexqCYIzhJDDQ9Dy6U1C6o4DX2fRJlhm9cEjrDZrr/VdTtdCLDsOcxmkBHHwqGsXn70TOvrKdv5boLwqU3ICvJvIIzlDiBSf/ESkJD2HUljMa8xrzPDKkvjqfXDcxVnOxrlgWTJ9BCHxn649bNMceSdK1OUdNb1LKTWnF+8G1PsGclQ1MLxqxVWJLR7/Dlgw3TXY+6IBrVqrnFCz7bPbA9L4lGADU6UsNcdqyn+XBblY5fE4uYe6xGwLisx0ikIBtt307b2aftukcfnwhBm8pQ/nvUm8hdRCJ/n0Plf4EEow"
	signature, _ := base64.RawStdEncoding.DecodeString(base64Signature)

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	s, err := New(sess, "not a key id", RSA_PKCS1_S256)
	assert.NoError(t, err)

	ok, err := s.Verify([]byte("Hello World"), signature)
	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestSize(t *testing.T) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	sizes := map[string]int{
		RSA_PSS_S256:   256,
		RSA_PSS_S384:   384,
		RSA_PSS_S512:   512,
		RSA_PKCS1_S256: 256,
		RSA_PKCS1_S384: 384,
		RSA_PKCS1_S512: 512,
		ECDSA_S256:     256,
		ECDSA_S384:     384,
		ECDSA_S512:     512,
	}

	for alg, expectedSize := range sizes {
		s, err := New(sess, testKeyId, alg)
		assert.NoError(t, err)

		size, err := s.Size()
		assert.NoError(t, err)
		assert.Equal(t, expectedSize, size)
	}
}

func TestSize_HavingUnsupportedAlg_ReturnsError(t *testing.T) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	s, err := New(sess, testKeyId, RSA_PKCS1_S256)
	assert.NoError(t, err)

	// Invalid arg, to simulate "out of bounds" error
	s.signingAlg = "32rn"

	size, err := s.Size()
	assert.NotNil(t, err)
	assert.Equal(t, 0, size)
}

func TestE2E(t *testing.T) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	s, err := New(sess, testKeyId, RSA_PKCS1_S256)
	assert.Nil(t, err)

	// Creating a new builder object, then adding some claims.
	builder, err := gojwt.New(s)
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

	err = jwt.Verify(s)
	assert.Nil(t, err)
}
