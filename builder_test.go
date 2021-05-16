package gojwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/reecerussell/gojwt/mock"
)

func TestNew_WhereAlgNameReturnsError_ReturnsError(t *testing.T) {
	testErr := errors.New("test error")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAlg := mock.NewMockAlgorithm(ctrl)
	mockAlg.EXPECT().Name().Return("", testErr)

	builder, err := New(mockAlg)
	assert.Nil(t, builder)
	assert.Equal(t, testErr, err)
}

func TestBuilderAddClaim(t *testing.T) {
	b, err := New(&testAlgorithm{})
	assert.NoError(t, err)

	b.AddClaim("myValue", 123)

	assert.Equal(t, 123, b.claims["myValue"])
}

func TestBuilderAddClaim_WithExistingName_ValueIsOveridden(t *testing.T) {
	b, err := New(&testAlgorithm{})
	assert.NoError(t, err)

	b.claims["myValue"] = 123

	b.AddClaim("myValue", "Hello World")

	assert.Equal(t, "Hello World", b.claims["myValue"])
}

func TestBuilderAddClaims(t *testing.T) {
	b, err := New(&testAlgorithm{})
	assert.NoError(t, err)

	myClaims := map[string]interface{}{
		"name": "John Doe",
		"age":  28,
	}

	b.AddClaims(myClaims)

	assert.Equal(t, "John Doe", b.claims["name"])
	assert.Equal(t, 28, b.claims["age"])
}

func TestBuilderSetExpiry(t *testing.T) {
	expiry := time.Now().UTC()
	b, err := New(&testAlgorithm{})
	assert.NoError(t, err)

	b.SetExpiry(expiry)

	expected := float64(expiry.UnixNano() / 1e9)
	assert.Equal(t, expected, b.claims[ExpiryClaim])
}

func TestBuilderSetNotBefore(t *testing.T) {
	notBefore := time.Now().UTC()
	b, err := New(&testAlgorithm{})
	assert.NoError(t, err)

	b.SetNotBefore(notBefore)

	expected := float64(notBefore.UnixNano() / 1e9)
	assert.Equal(t, expected, b.claims[NotBeforeClaim])
}

func TestBuilderSetIssuedAt(t *testing.T) {
	issuedAt := time.Now().UTC()
	b, err := New(&testAlgorithm{})
	assert.NoError(t, err)

	b.SetIssuedAt(issuedAt)

	expected := float64(issuedAt.UnixNano() / 1e9)
	assert.Equal(t, expected, b.claims[IssuedAtClaim])
}

func TestBuilderBuild(t *testing.T) {
	const expected string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJhZ2UiOjI4LCJuYW1lIjoiSm9obiJ9.D88aOvlyS4-4ljD8aX3YadibGzvDOQUgp8gyP75NHJE"

	builder, err := New(&testAlgorithm{})
	assert.NoError(t, err)

	token, err := builder.
		AddClaim("age", 28).
		AddClaim("name", "John").
		Build()

	assert.Nil(t, err)
	assert.Equal(t, expected, token)

	t.Run("Header Contains Correct Data", func(t *testing.T) {
		h := strings.Split(token, ".")[0]
		bytes, _ := base64.RawURLEncoding.DecodeString(h)
		var data map[string]interface{}
		json.Unmarshal(bytes, &data)

		assert.Equal(t, "JWT", data["typ"])
		assert.Equal(t, "test", data["alg"])
	})

	t.Run("Payload Contains Correct Data", func(t *testing.T) {
		h := strings.Split(token, ".")[1]
		bytes, _ := base64.RawURLEncoding.DecodeString(h)
		var data map[string]interface{}
		json.Unmarshal(bytes, &data)

		assert.Equal(t, 28, int(data["age"].(float64)))
		assert.Equal(t, "John", data["name"])
	})
}

func TestBuilderBuild_WhereSigningReturnsError_ReturnEmptyStringAndError(t *testing.T) {
	testErr := errors.New("test error")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAlg := mock.NewMockAlgorithm(ctrl)
	mockAlg.EXPECT().Name().Return("RS256", nil)
	mockAlg.EXPECT().Size().Return(256, nil)
	mockAlg.EXPECT().Sign(gomock.Any()).Return(nil, testErr)

	builder, err := New(mockAlg)
	assert.NoError(t, err)

	token, err := builder.
		AddClaim("age", 28).
		AddClaim("name", "John").
		Build()

	assert.Equal(t, testErr, err)
	assert.Equal(t, "", token)
}

func TestBuilderBuild_WhereAlgSizeReturnsError_ReturnsError(t *testing.T) {
	testErr := errors.New("test error")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAlg := mock.NewMockAlgorithm(ctrl)
	mockAlg.EXPECT().Name().Return("RS256", nil)
	mockAlg.EXPECT().Size().Return(0, testErr)

	builder, err := New(mockAlg)
	assert.NoError(t, err)

	token, err := builder.
		AddClaim("age", 28).
		AddClaim("name", "John").
		Build()

	assert.Equal(t, testErr, err)
	assert.Equal(t, "", token)
}
