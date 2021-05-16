package gojwt

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/reecerussell/gojwt/mock"
)

const testToken string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJhZ2UiOjI4LCJleHAiOjE2MDczMzg1OTYsIm5hbWUiOiJKb2huIn0.D88aOvlyS4-4ljD8aX3YadibGzvDOQUgp8gyP75NHJE"

func TestToken(t *testing.T) {
	jwt, err := Token(testToken)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)
	assert.Equal(t, "John", jwt.Claims["name"])
	assert.Equal(t, 28, int(jwt.Claims["age"].(float64)))
	assert.Equal(t, 1607338596, int(jwt.Claims["exp"].(float64)))
	assert.Equal(t, "test", jwt.h.Alg)
	assert.Equal(t, "JWT", jwt.h.Type)
	assert.Equal(t, testToken, jwt.raw)
}

func TestToken_GivenEmptyToken_ReturnsError(t *testing.T) {
	jwt, err := Token("")
	assert.Nil(t, jwt)
	assert.Equal(t, "token is empty", err.Error())
}

func TestToken_InvalidTokenStructure_ReturnsError(t *testing.T) {
	jwt, err := Token("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0")
	assert.Nil(t, jwt)
	assert.Equal(t, "invalid token structure", err.Error())
}

func TestToken_InvalidHeaderBase64_ReturnsError(t *testing.T) {
	jwt, err := Token("3ro++-erhwker.<payload>.<signature>")
	assert.Nil(t, jwt)
	assert.Equal(t, "header: invalid base64", err.Error())
}

func TestToken_InvalidHeaderJSON_ReturnsError(t *testing.T) {
	jwt, err := Token("eyJoZWxsbzoid29ybGQi.<payload>.<signature>")
	assert.Nil(t, jwt)
	assert.Equal(t, "header: invalid json", err.Error())
}

func TestToken_InvalidPayloadBase64_ReturnsError(t *testing.T) {
	jwt, err := Token("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.3ro++-erhwker.<signature>")
	assert.Nil(t, jwt)
	assert.Equal(t, "payload: invalid base64", err.Error())
}

func TestToken_InvalidPayloadJSON_ReturnsError(t *testing.T) {
	jwt, err := Token("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJoZWxsbzoid29ybGQi.<signature>")
	assert.Nil(t, jwt)
	assert.Equal(t, "payload: invalid json", err.Error())
}

func TestClaimsGetString(t *testing.T) {
	jwt, err := Token(testToken)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	v, ok := jwt.String("name")
	assert.Equal(t, "John", v)
	assert.True(t, ok)
}

func TestClaimsGetString_GivenNonExistantClaim_ReturnsFalse(t *testing.T) {
	jwt, err := Token(testToken)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	v, ok := jwt.String("location")
	assert.Equal(t, "", v)
	assert.False(t, ok)
}

func TestClaimsGetString_GivenNonStringClaim_ReturnsFalse(t *testing.T) {
	jwt, err := Token(testToken)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	v, ok := jwt.String("age")
	assert.Equal(t, "", v)
	assert.False(t, ok)
}

func TestClaimsGetInt(t *testing.T) {
	jwt, err := Token(testToken)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	v, ok := jwt.Int("age")
	assert.Equal(t, 28, v)
	assert.True(t, ok)
}

func TestClaimsGetInt_GivenNonExistantClaim_ReturnsFalse(t *testing.T) {
	jwt, err := Token(testToken)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	v, ok := jwt.Int("myNumber")
	assert.Equal(t, 0, v)
	assert.False(t, ok)
}

func TestClaimsGetInt_GivenNonNumberClaim_ReturnsFalse(t *testing.T) {
	jwt, err := Token(testToken)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	v, ok := jwt.Int("name")
	assert.Equal(t, 0, v)
	assert.False(t, ok)
}

func TestClaimsGetTime(t *testing.T) {
	jwt, err := Token(testToken)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	exp, ok := jwt.Time("exp")
	assert.Equal(t, time.Unix(1607338596, 0), exp)
	assert.True(t, ok)
}

func TestClaimsGetTime_GivenNonExistantClaim_ReturnsFalse(t *testing.T) {
	jwt, err := Token(testToken)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	exp, ok := jwt.Time("myTime")
	assert.Equal(t, time.Time{}, exp)
	assert.False(t, ok)
}

func TestClaimsGetTime_GivenNonNumberClaim_ReturnsFalse(t *testing.T) {
	jwt, err := Token(testToken)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	exp, ok := jwt.Time("name")
	assert.Equal(t, time.Time{}, exp)
	assert.False(t, ok)
}

func TestClaimsGetExpiry(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAlg := mock.NewMockAlgorithm(ctrl)
	mockAlg.EXPECT().Name().Return("RS256", nil)
	mockAlg.EXPECT().Size().Return(256, nil)
	mockAlg.EXPECT().Sign(gomock.Any()).DoAndReturn(func(data []byte) ([]byte, error) {
		sig := make([]byte, 256)
		rand.Read(sig)
		return sig, nil
	})

	now := time.Now().UTC()
	expiry := now.Add(1 * time.Hour)
	builder, err := New(mockAlg)
	assert.NoError(t, err)

	token, err := builder.
		SetExpiry(expiry).
		Build()
	if err != nil {
		panic(err)
	}

	jwt, err := Token(token)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	exp, ok := jwt.Expiry()
	assert.Equal(t, expiry.Unix(), exp.Unix())
	assert.True(t, ok)
}

func TestClaimsGetNotBefore(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAlg := mock.NewMockAlgorithm(ctrl)
	mockAlg.EXPECT().Name().Return("RS256", nil)
	mockAlg.EXPECT().Size().Return(256, nil)
	mockAlg.EXPECT().Sign(gomock.Any()).DoAndReturn(func(data []byte) ([]byte, error) {
		sig := make([]byte, 256)
		rand.Read(sig)
		return sig, nil
	})

	now := time.Now().UTC()
	builder, err := New(mockAlg)
	assert.NoError(t, err)

	token, err := builder.
		SetNotBefore(now).
		Build()
	if err != nil {
		panic(err)
	}

	jwt, err := Token(token)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	exp, ok := jwt.NotBefore()
	assert.Equal(t, now.Unix(), exp.Unix())
	assert.True(t, ok)
}

func TestClaimsGetIssuedAt(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAlg := mock.NewMockAlgorithm(ctrl)
	mockAlg.EXPECT().Name().Return("RS256", nil)
	mockAlg.EXPECT().Size().Return(256, nil)
	mockAlg.EXPECT().Sign(gomock.Any()).DoAndReturn(func(data []byte) ([]byte, error) {
		sig := make([]byte, 256)
		rand.Read(sig)
		return sig, nil
	})

	now := time.Now().UTC()
	builder, err := New(mockAlg)
	assert.NoError(t, err)

	token, err := builder.
		SetIssuedAt(now).
		Build()
	if err != nil {
		panic(err)
	}

	jwt, err := Token(token)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	exp, ok := jwt.IssuedAt()
	assert.Equal(t, now.Unix(), exp.Unix())
	assert.True(t, ok)
}

func TestTokenVerify(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAlg := mock.NewMockAlgorithm(ctrl)
	mockAlg.EXPECT().Name().Return("RS256", nil).Times(2)
	mockAlg.EXPECT().Size().Return(256, nil)
	mockAlg.EXPECT().Sign(gomock.Any()).DoAndReturn(func(data []byte) ([]byte, error) {
		sig := make([]byte, 256)
		rand.Read(sig)
		return sig, nil
	})
	mockAlg.EXPECT().Verify(gomock.Any(), gomock.Any()).Return(true, nil)

	now := time.Now().UTC()
	builder, err := New(mockAlg)
	assert.NoError(t, err)

	token, err := builder.
		SetNotBefore(now).
		SetExpiry(now.Add(1 * time.Hour)).
		Build()
	if err != nil {
		panic(err)
	}

	jwt, err := Token(token)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	err = jwt.Verify(mockAlg)
	assert.Nil(t, err)
}

func TestTokenVerify_GivenExpiredToken_ReturnsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAlg := mock.NewMockAlgorithm(ctrl)
	mockAlg.EXPECT().Name().Return("RS256", nil).Times(2)
	mockAlg.EXPECT().Size().Return(256, nil)
	mockAlg.EXPECT().Sign(gomock.Any()).DoAndReturn(func(data []byte) ([]byte, error) {
		sig := make([]byte, 256)
		rand.Read(sig)
		return sig, nil
	})
	mockAlg.EXPECT().Verify(gomock.Any(), gomock.Any()).Return(true, nil)

	now := time.Now().UTC()
	builder, err := New(mockAlg)
	assert.NoError(t, err)

	token, err := builder.
		SetExpiry(now.Add(-1 * time.Hour)).
		Build()
	if err != nil {
		panic(err)
	}

	jwt, err := Token(token)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	err = jwt.Verify(mockAlg)
	assert.Equal(t, "token has expired", err.Error())
}

func TestTokenVerify_GivenNotYetValidToken_ReturnsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAlg := mock.NewMockAlgorithm(ctrl)
	mockAlg.EXPECT().Name().Return("RS256", nil).Times(2)
	mockAlg.EXPECT().Size().Return(256, nil)
	mockAlg.EXPECT().Sign(gomock.Any()).DoAndReturn(func(data []byte) ([]byte, error) {
		sig := make([]byte, 256)
		rand.Read(sig)
		return sig, nil
	})
	mockAlg.EXPECT().Verify(gomock.Any(), gomock.Any()).Return(true, nil)

	now := time.Now().UTC()
	builder, err := New(mockAlg)
	assert.NoError(t, err)

	token, err := builder.
		SetNotBefore(now.Add(1 * time.Hour)).
		Build()
	if err != nil {
		panic(err)
	}

	jwt, err := Token(token)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	err = jwt.Verify(mockAlg)
	assert.Equal(t, "token is not yet valid", err.Error())
}

func TestTokenVerify_GivenTokenWithMismatchAlgName_ReturnsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAlg1 := mock.NewMockAlgorithm(ctrl)
	mockAlg1.EXPECT().Name().Return("RS256", nil)
	mockAlg1.EXPECT().Size().Return(256, nil)
	mockAlg1.EXPECT().Sign(gomock.Any()).DoAndReturn(func(data []byte) ([]byte, error) {
		sig := make([]byte, 256)
		rand.Read(sig)
		return sig, nil
	})

	mockAlg2 := mock.NewMockAlgorithm(ctrl)
	mockAlg2.EXPECT().Name().Return("RS512", nil)

	builder, err := New(mockAlg1)
	assert.NoError(t, err)

	token, err := builder.Build()
	if err != nil {
		panic(err)
	}

	jwt, err := Token(token)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	err = jwt.Verify(mockAlg2)
	assert.Equal(t, "algorithm mismatch", err.Error())
}

func TestTokenVerify_GivenInvalidSignature_ReturnsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAlg := mock.NewMockAlgorithm(ctrl)
	mockAlg.EXPECT().Name().Return("RS256", nil).Times(2)
	mockAlg.EXPECT().Size().Return(256, nil)
	mockAlg.EXPECT().Sign(gomock.Any()).DoAndReturn(func(data []byte) ([]byte, error) {
		sig := make([]byte, 256)
		rand.Read(sig)
		return sig, nil
	})
	mockAlg.EXPECT().Verify(gomock.Any(), gomock.Any()).Return(false, nil)

	builder, err := New(mockAlg)
	assert.NoError(t, err)

	token, err := builder.Build()
	if err != nil {
		panic(err)
	}

	jwt, err := Token(token)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	jwt.raw = jwt.raw[:len(jwt.raw)-2] // deform signature
	err = jwt.Verify(mockAlg)
	assert.Equal(t, "token is not valid", err.Error())
}

func TestTokenVerify_WhereSignatureVerificationFails_ReturnsError(t *testing.T) {
	testErr := errors.New("test error")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAlg := mock.NewMockAlgorithm(ctrl)
	mockAlg.EXPECT().Name().Return("RS256", nil).Times(2)
	mockAlg.EXPECT().Size().Return(256, nil)
	mockAlg.EXPECT().Sign(gomock.Any()).DoAndReturn(func(data []byte) ([]byte, error) {
		sig := make([]byte, 256)
		rand.Read(sig)
		return sig, nil
	})
	mockAlg.EXPECT().Verify(gomock.Any(), gomock.Any()).Return(false, testErr)

	builder, err := New(mockAlg)
	assert.NoError(t, err)

	token, err := builder.Build()
	if err != nil {
		panic(err)
	}

	jwt, err := Token(token)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	err = jwt.Verify(mockAlg)
	assert.Equal(t, testErr, err)
}

func TestVerify_WhereAlgNameReturnsError_ReturnsError(t *testing.T) {
	testErr := errors.New("test error")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAlg := mock.NewMockAlgorithm(ctrl)
	mockAlg.EXPECT().Name().Return("", testErr)

	jwt, err := Token(testToken)
	assert.Nil(t, err)
	assert.NotNil(t, jwt)

	err = jwt.Verify(mockAlg)
	assert.Equal(t, testErr, err)
}
