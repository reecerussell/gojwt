package kms

import (
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	awsKms "github.com/aws/aws-sdk-go/service/kms"
)

// A list of signing algorithms supported by AWS KMS.
const (
	RSA_PSS_S256   = "RSASSA_PSS_SHA_256"
	RSA_PSS_S384   = "RSASSA_PSS_SHA_384"
	RSA_PSS_S512   = "RSASSA_PSS_SHA_512"
	RSA_PKCS1_S256 = "RSASSA_PKCS1_V1_5_SHA_256"
	RSA_PKCS1_S384 = "RSASSA_PKCS1_V1_5_SHA_384"
	RSA_PKCS1_S512 = "RSASSA_PKCS1_V1_5_SHA_512"
	ECDSA_S256     = "ECDSA_SHA_256"
	ECDSA_S384     = "ECDSA_SHA_384"
	ECDSA_S512     = "ECDSA_SHA_512"
)

// A map of signing algorithms to their JWT alg types.
var signingAlgorithms = map[string]string{
	RSA_PSS_S256:   "RS256",
	RSA_PSS_S384:   "RS384",
	RSA_PSS_S512:   "RS512",
	RSA_PKCS1_S256: "RS256",
	RSA_PKCS1_S384: "RS384",
	RSA_PKCS1_S512: "RS512",
	ECDSA_S256:     "ES256",
	ECDSA_S384:     "ES384",
	ECDSA_S512:     "ES512",
}

var signingAlgorithmSizes = map[string]int{
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

// KMS is an implementation of gojwt.Algorithm for AWS's
// Key Management Service.
type KMS struct {
	svc        *awsKms.KMS
	keyId      string
	signingAlg string
}

// New returns a new instance of KMS for the given session and key.
func New(sess *session.Session, keyId, signingAlg string) (*KMS, error) {
	if sess == nil {
		return nil, errors.New("sess cannot contain a non-nil value")
	}

	_, ok := signingAlgorithms[signingAlg]
	if !ok {
		return nil, fmt.Errorf("the signing algorithm '%s' is not supported", signingAlg)
	}

	return &KMS{
		svc:        awsKms.New(sess),
		keyId:      keyId,
		signingAlg: signingAlg,
	}, nil
}

func (s *KMS) Name() (string, error) {
	return signingAlgorithms[s.signingAlg], nil
}

func (s *KMS) Sign(data []byte) ([]byte, error) {
	res, err := s.svc.Sign(&awsKms.SignInput{
		KeyId:            aws.String(s.keyId),
		Message:          data,
		MessageType:      aws.String("RAW"),
		SigningAlgorithm: aws.String(s.signingAlg),
	})
	if err != nil {
		return nil, err
	}

	return res.Signature, nil
}

func (s *KMS) Verify(data, signature []byte) (bool, error) {
	res, err := s.svc.Verify(&awsKms.VerifyInput{
		KeyId:            aws.String(s.keyId),
		Signature:        signature,
		Message:          data,
		MessageType:      aws.String("RAW"),
		SigningAlgorithm: aws.String(s.signingAlg),
	})
	if err != nil {
		return false, err
	}

	return *res.SignatureValid, nil
}

func (s *KMS) Size() (int, error) {
	if size, ok := signingAlgorithmSizes[s.signingAlg]; ok {
		return size, nil
	}

	return 0, errors.New("unsupported signing algorithm")
}
