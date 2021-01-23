package rsa

import (
	"crypto"
	"crypto/rand"
	rsapkg "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

// RSA is an implementation of the jwt.Algorithm interface,
// for RSA PKCS1v15.
type RSA struct {
	h   crypto.Hash
	k   *rsapkg.PrivateKey
	pub *rsapkg.PublicKey
}

// NewFromFile reads the file with the given name, then returns
// a new instance of RSA, configured with the given hash. The filename
// must relate to a PEM encoded RSA PKCS1v15 private key.
func NewFromFile(filename string, h crypto.Hash) (*RSA, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return New(bytes, h)
}

// New returns a new instance of RSA, where data is a PEM
// encoded RSA PKCS1v15 private key. An error is returned
// if either the PEM is invalid or the private key is invalid.
func New(data []byte, h crypto.Hash) (*RSA, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid key format")
	}

	var (
		key *rsapkg.PrivateKey
		pub *rsapkg.PublicKey
		err error
	)

	if block.Type == "PUBLIC KEY" {
		pk, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			pub = pk.(*rsapkg.PublicKey)
		}
	} else {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err == nil {
			pub = &(*key).PublicKey
		}
	}
	if err != nil {
		return nil, err
	}

	return &RSA{
		h:   h,
		k:   key,
		pub: pub,
	}, nil
}

// Name returns an algorithm name for use in a JWT header,
// i.e. RS256
func (alg *RSA) Name() string {
	var size int
	if alg.k != nil {
		size = alg.k.Size()
	} else {
		size = alg.pub.Size()
	}

	return fmt.Sprintf("RS%d", size)
}

// Sign signs the given data using the RSA PKCS1v15 private key,
// with the configured hash.
func (alg *RSA) Sign(data []byte) []byte {
	if alg.k == nil {
		panic("alg must contain a private key to sign token")
	}

	digest := alg.h.New()
	digest.Write(data)

	bytes, _ := rsapkg.SignPKCS1v15(rand.Reader, alg.k, alg.h, digest.Sum(nil))
	return bytes
}

// Verify validates the given data against the signature using the
// RSA PKCS1v15 key and the hash.
func (alg *RSA) Verify(data, signature []byte) bool {
	digest := alg.h.New()
	digest.Write(data)

	err := rsapkg.VerifyPKCS1v15(alg.pub, alg.h, digest.Sum(nil), signature)
	if err != nil {
		return false
	}

	return true
}

// Size returns the byte size of the configured hash.
func (alg *RSA) Size() int {
	return alg.k.Size()
}
