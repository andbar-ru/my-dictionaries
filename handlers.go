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
	tokenDetails, err := NewTokenDetails(user.Login)
	if err != nil {
		text := "failed to generate tokens"
		logger.Error("%s: %s", text, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": text})
		return
	}
	tokens := map[string]string{
		"access_token":  tokenDetails.AccessToken,
		"refresh_token": tokenDetails.RefreshToken,
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
