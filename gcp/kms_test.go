package gcp

import (
	"crypto"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	proto "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func init() {
	if os.Getenv("CI") == "" {
		os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "service-account.json")
	}
}

func TestGetDigestType_WhereKeyAlgIsSHA256_ReturnsDigest256(t *testing.T) {
	kms := KMS{
		key: &proto.CryptoKey{
			VersionTemplate: &proto.CryptoKeyVersionTemplate{
				Algorithm: proto.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			},
		},
	}
	data := []byte("hello world")
	digest := kms.getDigestType(data)
	assert.IsType(t, &proto.Digest_Sha256{}, digest.Digest)
	assert.Equal(t, data, digest.Digest.(*proto.Digest_Sha256).Sha256)
}

func TestGetDigestType_WhereKeyAlgIsSHA384_ReturnsDigest384(t *testing.T) {
	kms := KMS{
		key: &proto.CryptoKey{
			VersionTemplate: &proto.CryptoKeyVersionTemplate{
				Algorithm: proto.CryptoKeyVersion_EC_SIGN_P384_SHA384,
			},
		},
	}
	data := []byte("hello world")
	digest := kms.getDigestType(data)
	assert.IsType(t, &proto.Digest_Sha384{}, digest.Digest)
	assert.Equal(t, data, digest.Digest.(*proto.Digest_Sha384).Sha384)
}

func TestGetDigestType_WhereKeyAlgIsSHA512_ReturnsDigest512(t *testing.T) {
	kms := KMS{
		key: &proto.CryptoKey{
			VersionTemplate: &proto.CryptoKeyVersionTemplate{
				Algorithm: proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
			},
		},
	}
	data := []byte("hello world")
	digest := kms.getDigestType(data)
	assert.IsType(t, &proto.Digest_Sha512{}, digest.Digest)
	assert.Equal(t, data, digest.Digest.(*proto.Digest_Sha512).Sha512)
}

func TestGetDigestType_WhereKeyAlgIsUnsupported_Panics(t *testing.T) {
	kms := KMS{
		key: &proto.CryptoKey{
			VersionTemplate: &proto.CryptoKeyVersionTemplate{
				Algorithm: proto.CryptoKeyVersion_HMAC_SHA256, // unsupported alg
			},
		},
	}
	data := []byte("hello world")

	assert.PanicsWithError(t, ErrUnsupportedAlgorithm.Error(), func() {
		_ = kms.getDigestType(data)
	})
}

func TestName_GivenRSA256Algorithm_ReturnsCorrectName(t *testing.T) {
	algs := []proto.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
		proto.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
	}

	for _, alg := range algs {
		kms := KMS{
			key: &proto.CryptoKey{
				VersionTemplate: &proto.CryptoKeyVersionTemplate{
					Algorithm: alg,
				},
			},
		}
		name, err := kms.Name()
		assert.Nil(t, err)
		assert.Equal(t, "RS256", name)
	}
}

func TestName_GivenRSA512Algorithm_ReturnsCorrectName(t *testing.T) {
	algs := []proto.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
		proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
	}

	for _, alg := range algs {
		kms := KMS{
			key: &proto.CryptoKey{
				VersionTemplate: &proto.CryptoKeyVersionTemplate{
					Algorithm: alg,
				},
			},
		}
		name, err := kms.Name()
		assert.Nil(t, err)
		assert.Equal(t, "RS512", name)
	}
}

func TestName_GivenEC256Algorithm_ReturnsCorrectName(t *testing.T) {
	algs := []proto.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
		proto.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
	}

	for _, alg := range algs {
		kms := KMS{
			key: &proto.CryptoKey{
				VersionTemplate: &proto.CryptoKeyVersionTemplate{
					Algorithm: alg,
				},
			},
		}
		name, err := kms.Name()
		assert.Nil(t, err)
		assert.Equal(t, "EC256", name)
	}
}

func TestName_GivenEC384Algorithm_ReturnsCorrectName(t *testing.T) {
	kms := KMS{
		key: &proto.CryptoKey{
			VersionTemplate: &proto.CryptoKeyVersionTemplate{
				Algorithm: proto.CryptoKeyVersion_EC_SIGN_P384_SHA384,
			},
		},
	}
	name, err := kms.Name()
	assert.Nil(t, err)
	assert.Equal(t, "EC384", name)
}

func TestName_GivenUnsupportedAlg_ReturnsErr(t *testing.T) {
	kms := KMS{
		key: &proto.CryptoKey{
			VersionTemplate: &proto.CryptoKeyVersionTemplate{
				// Unsupported algorithm.
				Algorithm: proto.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1,
			},
		},
	}
	name, err := kms.Name()
	assert.Equal(t, ErrUnsupportedAlgorithm, err)
	assert.Equal(t, "", name)
}

func TestGetHashAlgorithm_GivenSHA256Alg_ReturnsSHA256Hash(t *testing.T) {
	algs := []proto.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
		proto.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
	}

	for _, alg := range algs {
		kms := KMS{
			key: &proto.CryptoKey{
				VersionTemplate: &proto.CryptoKeyVersionTemplate{
					Algorithm: alg,
				},
			},
		}
		h := kms.getHashAlgorithm()
		assert.Equal(t, crypto.SHA256, h)
	}
}

func TestGetHashAlgorithm_GivenSHA384Alg_ReturnsSHA384Hash(t *testing.T) {
	algs := []proto.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
		proto.CryptoKeyVersion_EC_SIGN_P384_SHA384,
	}

	for _, alg := range algs {
		kms := KMS{
			key: &proto.CryptoKey{
				VersionTemplate: &proto.CryptoKeyVersionTemplate{
					Algorithm: alg,
				},
			},
		}
		h := kms.getHashAlgorithm()
		assert.Equal(t, crypto.SHA384, h)
	}
}

func TestGetHashAlgorithm_GivenSHA512Alg_ReturnsSHA512Hash(t *testing.T) {
	algs := []proto.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
		proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
	}

	for _, alg := range algs {
		kms := KMS{
			key: &proto.CryptoKey{
				VersionTemplate: &proto.CryptoKeyVersionTemplate{
					Algorithm: alg,
				},
			},
		}
		h := kms.getHashAlgorithm()
		assert.Equal(t, crypto.SHA512, h)
	}
}

func TestGetHashAlgorithm_GivenUnsupportedAlg_Panics(t *testing.T) {
	kms := KMS{
		key: &proto.CryptoKey{
			VersionTemplate: &proto.CryptoKeyVersionTemplate{
				// Unsupported algorithm.
				Algorithm: proto.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1,
			},
		},
	}
	assert.PanicsWithError(t, ErrUnsupportedAlgorithm.Error(), func() {
		_ = kms.getHashAlgorithm()
	})
}

func TestVerify_GivenInvalidSignature_ReturnsFalse(t *testing.T) {
	for name, keyId := range keys {
		t.Run(name, func(t *testing.T) {
			kms, _ := New(keyId)
			data := []byte("hello world")
			sig := []byte("invalid signature")
			ok, err := kms.Verify(data, sig)
			assert.Nil(t, err)
			assert.False(t, ok)
		})
	}
}

func TestVerify_WhereKeyAlgIsUnsupported_ReturnsErr(t *testing.T) {
	kms := KMS{
		key: &proto.CryptoKey{
			VersionTemplate: &proto.CryptoKeyVersionTemplate{
				// Unsupported algorithm.
				Algorithm: proto.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1,
			},
		},
	}
	data := []byte("hello world")
	signature := []byte("signature")
	ok, err := kms.Verify(data, signature)
	assert.False(t, ok)
	assert.Equal(t, ErrUnsupportedAlgorithm, err)
}

func TestSize_GivenSHA256Alg_Returns256(t *testing.T) {
	algs := []proto.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
		proto.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		proto.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
	}

	for _, alg := range algs {
		kms := KMS{
			key: &proto.CryptoKey{
				VersionTemplate: &proto.CryptoKeyVersionTemplate{
					Algorithm: alg,
				},
			},
		}
		size, err := kms.Size()
		assert.Nil(t, err)
		assert.Equal(t, 256, size)
	}
}

func TestSize_GivenSHA384Alg_Returns384(t *testing.T) {
	algs := []proto.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
		proto.CryptoKeyVersion_EC_SIGN_P384_SHA384,
	}

	for _, alg := range algs {
		kms := KMS{
			key: &proto.CryptoKey{
				VersionTemplate: &proto.CryptoKeyVersionTemplate{
					Algorithm: alg,
				},
			},
		}
		size, err := kms.Size()
		assert.Nil(t, err)
		assert.Equal(t, 384, size)
	}
}

func TestSize_GivenSHA512Alg_Returns512(t *testing.T) {
	algs := []proto.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
		proto.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
		proto.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
	}

	for _, alg := range algs {
		kms := KMS{
			key: &proto.CryptoKey{
				VersionTemplate: &proto.CryptoKeyVersionTemplate{
					Algorithm: alg,
				},
			},
		}
		size, err := kms.Size()
		assert.Nil(t, err)
		assert.Equal(t, 512, size)
	}
}

func TestSize_GivenUnsupportedAlg_ReturnError(t *testing.T) {
	kms := KMS{
		key: &proto.CryptoKey{
			VersionTemplate: &proto.CryptoKeyVersionTemplate{
				// Unsupported algorithm.
				Algorithm: proto.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1,
			},
		},
	}
	size, err := kms.Size()
	assert.Equal(t, ErrUnsupportedAlgorithm, err)
	assert.Equal(t, 0, size)
}
