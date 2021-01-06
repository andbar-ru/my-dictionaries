package main

import (
	"net/http"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

// handleGetTest handles /api/test.
func handleGetTest(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	c.JSON(http.StatusOK, gin.H{
		"login": claims[identityKey],
	})
}
