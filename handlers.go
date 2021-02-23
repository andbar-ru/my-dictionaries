package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// handleLogin handles /login.
func handleLogin(c *gin.Context) {
	login, password, hasAuth := c.Request.BasicAuth()
	if !hasAuth {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "missing username or password"})
		return
	}
	passwordHash, err := userGetPasswordHash(login)
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
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "incorrect username or password"})
		return
	}
	accessToken, refreshToken, err := generateTokens(login)
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

// handleLogout handles /logout.
func handleLogout(c *gin.Context) {
	token, err := extractToken(c.Request)
	if err != nil {
		text := "failed to extract JWT token"
		logger.Error("%s: %s", text, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": text})
		return
	}
	loginI, _ := token.Get("login")
	login, _ := loginI.(string)
	if login == "" {
		text := "failed to fetch login from token"
		logger.Error("%s: %s", text, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": text})
		return
	}
	err = userClearTokens(login)
	if err != nil {
		text := "failed to clear tokens of user " + login
		logger.Error("%s: %s", text, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": text})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
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

	refreshToken, err := validateToken(refreshTokenStr, RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "refresh token is not valid or expired"})
		return
	}

	// Create new pair of access and refresh tokens.
	loginI, _ := refreshToken.Get("login")
	login, _ := loginI.(string)
	if login == "" {
		text := "unexpected error: could not find login in refresh token"
		logger.Error(text)
		c.JSON(http.StatusInternalServerError, gin.H{"error": text})
		return
	}
	newAccessToken, newRefreshToken, err := generateTokens(login)
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
