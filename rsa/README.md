# RSA

The RSA package provides support for signing and verifing tokens using an asymmetric PKCS1v15 key.

## Usage

There are two ways of using the RSA algorithm, either with PEM-encoded RSA private key data, or with it as a file.

#### As a file:

```go
const myPrivateKeyFile string = "./super_secret_key.pem"
alg, err := rsa.NewFromFile(myPrivateKeyFile, crypto.SHA256)
if err != nil {
    panic(err)
}
```

#### Byte slice

```go
var bytes []byte // PEM data
alg, err := rsa.New(bytes, crypto.SHA256)
if err != nil {
    panic(err)
}
```
