package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func JWTMiddleware(c *gin.Context) {
	err := validateRequestToken(c.Request)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "unauthorized", "error": err.Error()})
	}
	c.Next()
}
