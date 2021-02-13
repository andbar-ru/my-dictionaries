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

func GetSignedTokens(login string) (string, string, error) {
	accessToken := jwt.New()
	accessToken.Set(jwt.JwtIDKey, uuid.NewV4().String())
	accessToken.Set(jwt.SubjectKey, config.JWTConfig.Subject)
	accessToken.Set("login", login)
	accessToken.Set(jwt.ExpirationKey, time.Now().Add(time.Duration(config.JWTConfig.AccessKeyLifetime)*time.Second).Unix())
	signed, err := jwt.Sign(accessToken, jwa.HS256, accessKey)
	if err != nil {
		return "", "", err
	}
	signedAccessToken := string(signed)

	refreshToken := jwt.New()
	refreshToken.Set(jwt.JwtIDKey, uuid.NewV4().String())
	refreshToken.Set(jwt.SubjectKey, config.JWTConfig.Subject)
	refreshToken.Set("login", login)
	refreshToken.Set(jwt.ExpirationKey, time.Now().Add(time.Duration(config.JWTConfig.RefreshKeyLifeTime)*time.Second).Unix())
	signed, err = jwt.Sign(refreshToken, jwa.HS256, refreshKey)
	if err != nil {
		return "", "", err
	}
	signedRefreshToken := string(signed)

	return signedAccessToken, signedRefreshToken, nil
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
