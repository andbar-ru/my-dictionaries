package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/lestrrat-go/jwx/jwk"
)

// Global variables
var (
	config        *Config
	logger        *Logger
	db            *sqlx.DB
	accessKey     jwk.Key
	accessKeySet  jwk.Set
	refreshKey    jwk.Key
	refreshKeySet jwk.Set
)

// init initializes global variables.
func init() {
	config = GetConfig()
	logger = NewLogger(config.LogConfig)
	var err error
	// Must be "=", else `db` is not available in handlers.
	db, err = getDB()
	checkErr(err)
	initKeySets()
}

func main() {
	defer closeCheck(db)

	router := gin.Default()
	router.GET("/login", handleLogin)
	router.POST("/refresh_token", handleRefreshToken)
	router.GET("/logout", JWTMiddleware, handleLogout)

	api := router.Group("/api")
	api.Use(JWTMiddleware)
	api.GET("/test", handleTest)

	if err := router.Run(config.ListenAddress); err != nil {
		log.Fatalf("Could not run server: %v", err)
	}
}
