package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func JWTMiddleware(c *gin.Context) {
	err := validateToken(c.Request)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
	}
	c.Next()
}
