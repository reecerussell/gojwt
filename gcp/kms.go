package gcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"math/big"
	"regexp"
	"sync"
	"time"

	pkg "cloud.google.com/go/kms/apiv1"
	"github.com/pkg/errors"
	proto "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ErrUnsupportedAlgorithm is an error used to indicate the GCP key's
// algorithm is unsupported by gojwt.
var ErrUnsupportedAlgorithm = errors.New("gojwt: unsupported algorithm")

// KMS is an implementation of gojwt.Algorithm for Google Cloud
// Platform's Key Management Service.
type KMS struct {
	client  *pkg.KeyManagementClient
	keyName string
	key     *proto.CryptoKey

	// The mutex is used to block concurrent calls to fetch the public key.
	mu sync.Mutex
	// If set, this is the raw data of the public key in PEM format.
	pubKeyData []byte
}

// New is used to instantiate a new version of KMS for the given key.
// Note the the cryptoKeyVersion must be specified in the key name,
// i.e. <key-name>/cryptoKeyVersions/1.
func New(keyName string) (*KMS, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	client, err := pkg.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gojwt: failed to init kms: %v", err)
	}

	key, err := client.GetCryptoKey(context.Background(), &proto.GetCryptoKeyRequest{
		Name: regexp.MustCompile(`\/cryptoKeyVersions\/[0-9]+`).ReplaceAllString(keyName, ""),
	})
	if err != nil {
		return nil, fmt.Errorf("gojwt: failed to fetch key: %v", err)
	}
	if key.GetPurpose() != proto.CryptoKey_ASYMMETRIC_SIGN {
		return nil, fmt.Errorf("gojwt: the specified key has the wrong purpose")
	}
	return &KMS{
		client:  client,
		keyName: keyName,
		key:     key,
		mu:      sync.Mutex{},
	}, nil
}

func (kms *KMS) Name() (string, error) {
	switch kms.key.GetVersionTemplate().Algorithm {
	case proto.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		return "RS256", nil
	case proto.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256:
		return "EC256", nil
	case proto.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return "EC384", nil
	case proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		return "RS512", nil
	default:
		return "", ErrUnsupportedAlgorithm
	}
}

func (kms *KMS) Sign(data []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	digest := kms.getHashAlgorithm().New()
	_, _ = digest.Write(data)
	req := &proto.AsymmetricSignRequest{
		Name:         kms.keyName,
		DigestCrc32C: wrapperspb.Int64(crc32c(digest.Sum(nil))),
		Digest:       kms.getDigestType(digest.Sum(nil)),
	}
	resp, err := kms.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %v", err)
	}
	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if !resp.VerifiedDigestCrc32C {
		return nil, fmt.Errorf("failed to verify digest: request corrupted in-transit")
	}
	if crc32c(resp.Signature) != resp.SignatureCrc32C.Value {
		return nil, fmt.Errorf("fail to verify signature: request corrupted in-transit")
	}
	return resp.GetSignature(), nil
}

func crc32c(digest []byte) int64 {
	crc32t := crc32.MakeTable(crc32.Castagnoli)
	digestCRC32C := crc32.Checksum(digest, crc32t)
	return int64(digestCRC32C)
}

func (kms *KMS) Verify(data, signature []byte) (bool, error) {
	alg := kms.key.GetVersionTemplate().Algorithm
	switch alg {
	case proto.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		return kms.verifyRSAPKCS1(data, signature)
	case proto.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:
		return kms.verifyRSAPSS(data, signature)
	case proto.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return kms.verifyEC(data, signature)
	default:
		return false, ErrUnsupportedAlgorithm
	}
}

func (kms *KMS) verifyRSAPSS(data, signature []byte) (bool, error) {
	key, err := kms.getRSAPublicKey()
	if err != nil {
		return false, err
	}
	alg := kms.getHashAlgorithm()
	digest := alg.New()
	_, _ = digest.Write(data)
	err = rsa.VerifyPSS(key, alg, digest.Sum(nil), signature, &rsa.PSSOptions{
		SaltLength: len(digest.Sum(nil)),
		Hash:       alg,
	})
	if err != nil {
		// Ignore error, verification failed.
		return false, nil
	}
	return true, nil
}

func (kms *KMS) verifyRSAPKCS1(data, signature []byte) (bool, error) {
	key, err := kms.getRSAPublicKey()
	if err != nil {
		return false, err
	}
	alg := kms.getHashAlgorithm()
	digest := alg.New()
	_, _ = digest.Write(data)
	err = rsa.VerifyPKCS1v15(key, alg, digest.Sum(nil), signature)
	if err != nil {
		// Ignore error, verification failed.
		return false, nil
	}
	return true, nil
}

// Gets the KMS public key data and parses it as an RSA key.
func (kms *KMS) getRSAPublicKey() (*rsa.PublicKey, error) {
	data, err := kms.getPublicKeyData()
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PublicKey), nil
}

// verifyEC is used to verify elliptic curve signatures.
func (kms *KMS) verifyEC(data, signature []byte) (bool, error) {
	pemData, err := kms.getPublicKeyData()
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(pemData)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}
	ecKey := key.(*ecdsa.PublicKey)
	var parsedSig struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(signature, &parsedSig)
	if err != nil {
		// Signature is not a valid elliptic curve signature.
		return false, nil
	}
	digest := kms.getHashAlgorithm().New()
	_, _ = digest.Write(data)
	ok := ecdsa.Verify(ecKey, digest.Sum(nil), parsedSig.R, parsedSig.S)
	return ok, nil
}

func (kms *KMS) getPublicKeyData() ([]byte, error) {
	kms.mu.Lock()
	defer kms.mu.Unlock()
	if kms.pubKeyData != nil {
		return kms.pubKeyData, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	response, err := kms.client.GetPublicKey(ctx, &proto.GetPublicKeyRequest{
		Name: kms.keyName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}
	kms.pubKeyData = []byte(response.GetPem())
	return kms.pubKeyData, nil
}

func (kms *KMS) Size() (int, error) {
	alg := kms.key.GetVersionTemplate().Algorithm
	switch alg {
	case proto.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256:
		return crypto.SHA256.Size(), nil
	case proto.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return crypto.SHA384.Size(), nil
	case proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		return crypto.SHA512.Size(), nil
	default:
		return 0, ErrUnsupportedAlgorithm
	}
}

// Hash returns the relavent hashing algorithm for the key's algorithm,
// i.e. if the algorithm is CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, a SHA256
// hashing algorithm will be returned.
func (kms *KMS) getHashAlgorithm() crypto.Hash {
	alg := kms.key.GetVersionTemplate().Algorithm
	switch alg {
	case proto.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256:
		return crypto.SHA256
	case proto.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return crypto.SHA384
	case proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		return crypto.SHA512
	default:
		panic(ErrUnsupportedAlgorithm)
	}
}

// getDigestType is used to construct the protobuf type used to transport a digest.
func (kms *KMS) getDigestType(digest []byte) *proto.Digest {
	switch kms.key.GetVersionTemplate().Algorithm {
	case proto.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256:
		return &proto.Digest{
			Digest: &proto.Digest_Sha256{
				Sha256: digest,
			},
		}
	case proto.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return &proto.Digest{
			Digest: &proto.Digest_Sha384{
				Sha384: digest,
			},
		}
	case proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		return &proto.Digest{
			Digest: &proto.Digest_Sha512{
				Sha512: digest,
			},
		}
	default:
		panic(ErrUnsupportedAlgorithm)
	}
}
