[![Go Report Card](https://goreportcard.com/badge/github.com/reecerussell/gojwt)](https://goreportcard.com/badge/github.com/reecerussell/gojwt)
[![codecov](https://codecov.io/gh/reecerussell/gojwt/branch/master/graph/badge.svg)](https://codecov.io/gh/reecerussell/gojwt)
[![Go Docs](https://godoc.org/github.com/reecerussell/gojwt?status.svg)](https://godoc.org/github.com/reecerussell/gojwt)

# GOJWT

A simple, extendible JSON-Web-Token library, written in Golang with no third-party dependencies.

## Installation

Simply, just run this command to install the package into your module.

```
$ go get -u github.com/reecerussell/gojwt
```

## Supported Algorithms

-   [RSA](/rsa)
-   [AWS KMS](/kms)

## Usage

This package is based on a JWt builder object, which is used to construct the token and sign it. And an algorithm interface, which allows abstractions to be created to support many differnt signing algorithms.

Here is a basic example of using an algorithm and builder:

```go
// Initiating an Algorithm, in this case RSA.
const myPrivateKeyFile string = "./super_secret_key.pem"
alg, err := rsa.NewFromFile(myPrivateKeyFile, crypto.SHA256)
if err != nil {
    panic(err)
}

// Creating a new builder object, then adding some claims.
builder, err := gojwt.New(alg)
if err != nil {
    panic(err)
}

builder.AddClaim("name", "John Doe").
    SetExpiry(time.Now().Add(1 * time.Hour))

// Finally, building the token.
token, err := builder.Build()
if err != nil {
    panic(err)
}

fmt.Println(token)
```
