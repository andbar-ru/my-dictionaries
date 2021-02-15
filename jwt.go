package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/twinj/uuid"
)

type TokenType string

const (
	AccessToken  TokenType = "AccessToken"
	RefreshToken TokenType = "RefreshToken"
)

func generateTokens(login string) (string, string, error) {
	// Generate access token
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

	// Generate refresh token
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

	// Save tokens to database.
	_, err = db.NamedExec("UPDATE users SET access_token=:access_token, refresh_token=:refresh_token WHERE login=:login", User{
		Login:        login,
		AccessToken:  signedAccessToken,
		RefreshToken: signedRefreshToken,
	})
	if err != nil {
		return "", "", fmt.Errorf("could not save tokens to db: %s", err.Error())
	}

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

func validateRequestToken(r *http.Request) error {
	token, err := extractTokenString(r)
	if err != nil {
		return err
	}
	_, err = validateToken(token, AccessToken)
	if err != nil {
		return err
	}
	return nil
}

func validateToken(tokenString string, tokenType TokenType) (jwt.Token, error) {
	if tokenType != AccessToken && tokenType != RefreshToken {
		err := fmt.Errorf("unexpected token type %s", tokenType)
		logger.Error(err.Error())
		return nil, err
	}

	var token jwt.Token
	var err error

	switch tokenType {
	case AccessToken:
		token, err = jwt.ParseString(tokenString, jwt.WithKeySet(accessKeySet))
	case RefreshToken:
		token, err = jwt.ParseString(tokenString, jwt.WithKeySet(refreshKeySet))
	}

	if err != nil {
		return nil, errors.New("could not parse signed token")
	}

	loginI, _ := token.Get("login")
	login, _ := loginI.(string)
	if login == "" {
		return nil, errors.New("could not find login in token")
	}

	var dbToken string

	switch tokenType {
	case AccessToken:
		err = db.QueryRowx("SELECT access_token FROM users WHERE login = ?", login).Scan(&dbToken)
	case RefreshToken:
		err = db.QueryRowx("SELECT refresh_token FROM users WHERE login = ?", login).Scan(&dbToken)
	}

	if err != nil {
		return nil, errors.New("token is not valid")
	}
	if tokenString != dbToken {
		return nil, errors.New("token is not valid")
	}

	err = jwt.Validate(token)
	if err != nil {
		return nil, errors.New("token is expired")
	}

	return token, nil
}

func extractTokenString(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	authHeaderParts := strings.Split(authHeader, "Bearer ")
	if len(authHeaderParts) < 2 {
		return "", errors.New("there is not bearer authorization")
	}
	token := authHeaderParts[1]
	return token, nil
}

func extractToken(r *http.Request) (jwt.Token, error) {
	extractTokenStr, err := extractTokenString(r)
	if err != nil {
		return nil, err
	}
	token, err := jwt.ParseString(extractTokenStr, jwt.WithKeySet(accessKeySet))
	if err != nil {
		return nil, err
	}
	return token, nil
}
