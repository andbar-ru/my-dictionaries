package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/twinj/uuid"
)

type TokenDetails struct {
	AccessToken         string
	RefreshToken        string
	AccessTokenUuid     string
	RefreshTokenUuid    string
	AccessTokenExpires  int64
	RefreshTokenExpires int64
}

func NewTokenDetails(login string) (*TokenDetails, error) {
	tokenDetails := &TokenDetails{}
	tokenDetails.AccessTokenUuid = uuid.NewV4().String()
	tokenDetails.AccessTokenExpires = time.Now().Add(time.Duration(config.JWTConfig.AccessKeyLifetime) * time.Second).Unix()
	tokenDetails.RefreshTokenUuid = uuid.NewV4().String()
	tokenDetails.RefreshTokenExpires = time.Now().Add(time.Duration(config.JWTConfig.RefreshKeyLifeTime) * time.Second).Unix()

	var err error

	accessToken := jwt.New()
	accessToken.Set(jwt.JwtIDKey, tokenDetails.AccessTokenUuid)
	accessToken.Set(jwt.SubjectKey, config.JWTConfig.Subject)
	accessToken.Set("login", login)
	accessToken.Set(jwt.ExpirationKey, tokenDetails.AccessTokenExpires)
	signed, err := jwt.Sign(accessToken, jwa.HS256, accessKey)
	if err != nil {
		return nil, err
	}
	tokenDetails.AccessToken = string(signed)

	refreshToken := jwt.New()
	refreshToken.Set(jwt.JwtIDKey, tokenDetails.RefreshTokenUuid)
	refreshToken.Set(jwt.SubjectKey, config.JWTConfig.Subject)
	refreshToken.Set("login", login)
	refreshToken.Set(jwt.ExpirationKey, tokenDetails.RefreshTokenExpires)
	signed, err = jwt.Sign(refreshToken, jwa.HS256, refreshKey)
	if err != nil {
		return nil, err
	}
	tokenDetails.RefreshToken = string(signed)

	return tokenDetails, nil
}

// initKeySets initializes global variables concerning jwt keys.
func initKeySets() {
	// accessKey and refreshKey are global variables, so...
	var err error

	accessKey, err = jwk.New([]byte(config.JWTConfig.AccessKey))
	checkErr(err)
	accessKey.Set(jwk.KeyIDKey, "access_key")
	accessKeySet = jwk.NewSet()
	accessKeySet.Add(accessKey)

	refreshKey, err = jwk.New([]byte(config.JWTConfig.RefreshKey))
	checkErr(err)
	refreshKey.Set(jwk.KeyIDKey, "refresh_key")
	refreshKeySet = jwk.NewSet()
	refreshKeySet.Add(refreshKey)
}

func validateToken(r *http.Request) error {
	token, err := extractToken(r)
	if err != nil {
		return err
	}
	err = jwt.Validate(token, jwt.WithSubject(config.JWTConfig.Subject))
	if err != nil {
		return errors.New("token is not valid")
	}
	loginI, ok := token.Get("login")
	login, loginIsString := loginI.(string)
	if !ok || !loginIsString || login == "" {
		return errors.New("token is not valid")
	}
	return nil
}

func extractToken(r *http.Request) (jwt.Token, error) {
	authHeader := r.Header.Get("Authorization")
	authHeaderParts := strings.Split(authHeader, "Bearer ")
	if len(authHeaderParts) < 2 {
		return nil, errors.New("there is not bearer authorization")
	}
	tokenStr := authHeaderParts[1]
	token, err := jwt.ParseString(tokenStr, jwt.WithKeySet(accessKeySet))
	if err != nil {
		return nil, err
	}
	return token, nil
}
