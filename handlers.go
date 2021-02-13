package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/crypto/bcrypt"
)

// handleLogin handles /login.
func handleLogin(c *gin.Context) {
	login, password, hasAuth := c.Request.BasicAuth()
	if !hasAuth {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "missing username or password"})
		return
	}
	var user User
	err := db.QueryRowx("SELECT login, password_hash FROM users WHERE login = ?", login).StructScan(&user)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "incorrect username or password"})
			return
		}
		text := "unexpected server error"
		logger.Error("%s: %s", text, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": text})
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "incorrect username or password"})
		return
	}
	accessToken, refreshToken, err := GetSignedTokens(user.Login)
	if err != nil {
		text := "failed to generate tokens"
		logger.Error("%s: %s", text, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": text})
		return
	}
	tokens := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}
	c.JSON(http.StatusOK, tokens)
}

// handleRefreshToken handles /refresh_token.
func handleRefreshToken(c *gin.Context) {
	mapToken := make(map[string]string)
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"message": "could not find json body"})
		return
	}
	refreshTokenStr, ok := mapToken["refresh_token"]
	if !ok {
		c.JSON(http.StatusUnprocessableEntity, "could not find 'refresh_token' in request body")
		return
	}

	// Validate refresh token.
	refreshToken, err := jwt.ParseString(refreshTokenStr, jwt.WithKeySet(refreshKeySet))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "refresh token is not valid"})
		return
	}
	err = validateToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "refresh token is not valid or expired"})
		return
	}

	// Create new pair of access and refresh tokens.
	loginI, ok := refreshToken.Get("login")
	login, loginIsString := loginI.(string)
	if !ok || !loginIsString || login == "" {
		text := "unexpected error: could not find login in refresh token"
		logger.Error(text)
		c.JSON(http.StatusInternalServerError, gin.H{"error": text})
		return
	}
	newAccessToken, newRefreshToken, err := GetSignedTokens(login)
	if err != nil {
		text := "failed to generate tokens"
		logger.Error("%s: %s", text, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": text})
		return
	}
	tokens := map[string]string{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	}
	c.JSON(http.StatusOK, tokens)
}

// handleTest handles /api/test.
func handleTest(c *gin.Context) {
	token, err := extractToken(c.Request)
	if err != nil {
		text := "failed to extract JWT token"
		logger.Error("%s: %s", text, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": text})
		return
	}
	login, ok := token.Get("login")
	if !ok {
		text := "failed to fetch login from token"
		logger.Error(text)
		c.JSON(http.StatusInternalServerError, gin.H{"error": text})
		return
	}
	c.JSON(http.StatusOK, gin.H{"login": login})
}
