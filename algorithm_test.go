package gojwt

import (
	"crypto/hmac"
	"crypto/sha256"
)

type testAlgorithm struct {
	algName string
}

func (a *testAlgorithm) Name() string {
	if a.algName != "" {
		return a.algName
	}

	return "test"
}

func (a *testAlgorithm) Sign(token []byte) []byte {
	mac := hmac.New(sha256.New, []byte("test-key"))
	mac.Write(token)
	return mac.Sum(nil)
}

func (a *testAlgorithm) Verify(token, signature []byte) bool {
	mac := hmac.New(sha256.New, []byte("test-key"))
	mac.Write(token)
	expected := mac.Sum(nil)

	return hmac.Equal(expected, signature)
}

func (*testAlgorithm) Size() int {
	return sha256.New().Size()
}
