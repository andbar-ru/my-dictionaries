package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

const (
	identityKey = "login"
)

var (
	config *Config
	logger *Logger
	db     *sqlx.DB
)

func main() {
	config = GetConfig()
	logger = NewLogger(config.LogConfig)
	var err error
	// Must be "=", else `db` is not available in handlers.
	db, err = getDB()
	checkErr(err)
	defer closeCheck(db)

	jwtMiddleware, err := NewJWTMiddlware(config.JWTConfig)
	if err != nil {
		log.Fatal(err)
	}

	router := gin.Default()
	router.GET("/login", jwtMiddleware.LoginHandler)
	router.GET("/refresh_token", jwtMiddleware.MiddlewareFunc(), jwtMiddleware.RefreshHandler)

	api := router.Group("/api")
	api.Use(jwtMiddleware.MiddlewareFunc())
	api.GET("/test", handleGetTest)

	if err := router.Run(config.ListenAddress); err != nil {
		log.Fatalf("Could not run server: %v", err)
	}
}
