package gojwt

// Algorithm is an interface used to sign and verify
// JSON-Web-Tokens, as well as provide information
// to help generate and validate a token.
type Algorithm interface {
	// Name returns the signing algorithm name, to be used
	// in the header of a JSON-Web-Token.
	//
	// For example: "RS256", which will look like this, in use:
	// {"alg":"RS256"}
	Name() (string, error)

	// Sign is used to generate a signature of a token.
	Sign(data []byte) ([]byte, error)

	// Verify is used to validate the signature against the rest
	// of a token's data.
	//
	// An error is returned if the verification failed, however,
	// an error will not be thrown just because the signature is invalid.
	Verify(data, signature []byte) (bool, error)

	// Sign returns the hash byte count of the algorithm.
	//
	// For example: SHA256 will return 256.
	Size() (int, error)
}
