package gcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A set of keys used for testing (name=keyId).
var keys = map[string]string{
	"RSA-PSS-SHA256": "projects/used-for-testing-001/locations/europe-west1/keyRings/gojwt/cryptoKeys/rsa-pss-256/cryptoKeyVersions/1",
	"RSA-PKCS1":      "projects/used-for-testing-001/locations/europe-west1/keyRings/gojwt/cryptoKeys/rsa-pkcs1-256/cryptoKeyVersions/1",
	"EC-256":         "projects/used-for-testing-001/locations/europe-west1/keyRings/gojwt/cryptoKeys/ec-256/cryptoKeyVersions/1",
	"EC-384":         "projects/used-for-testing-001/locations/europe-west1/keyRings/gojwt/cryptoKeys/ec-384/cryptoKeyVersions/1",
}

func TestE2ESigningAndVerifying(t *testing.T) {
	for name, keyId := range keys {
		t.Run(name, func(t *testing.T) {
			kms, err := New(keyId)
			assert.Nil(t, err)

			data := []byte("Hello World")
			sig, err := kms.Sign(data)
			assert.Nil(t, err)

			ok, err := kms.Verify(data, sig)
			assert.Nil(t, err)
			assert.True(t, ok)
		})
	}
}
