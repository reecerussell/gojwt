package gojwt

import (
	"crypto/hmac"
	"crypto/sha256"
)

type testAlgorithm struct {
	algName string
}

func (a *testAlgorithm) Name() (string, error) {
	if a.algName != "" {
		return a.algName, nil
	}

	return "test", nil
}

func (a *testAlgorithm) Sign(token []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte("test-key"))
	mac.Write(token)
	return mac.Sum(nil), nil
}

func (a *testAlgorithm) Verify(token, signature []byte) (bool, error) {
	mac := hmac.New(sha256.New, []byte("test-key"))
	mac.Write(token)
	expected := mac.Sum(nil)

	return hmac.Equal(expected, signature), nil
}

func (*testAlgorithm) Size() (int, error) {
	return sha256.New().Size(), nil
}
