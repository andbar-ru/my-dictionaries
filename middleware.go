package main

import (
	"database/sql"
	"fmt"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// NewJWTMiddlware returns GinJWTMiddleware that provides a Json-Web-Token authentication implementation
// based on jwt config.
func NewJWTMiddlware(config *JWTConfig) (*jwt.GinJWTMiddleware, error) {
	jwtMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       config.Realm,
		Key:         []byte(config.Key),
		Timeout:     time.Second * time.Duration(config.Timeout),
		MaxRefresh:  time.Second * time.Duration(config.MaxRefresh),
		IdentityKey: identityKey,
		Authenticator: func(c *gin.Context) (interface{}, error) {
			login, password, hasAuth := c.Request.BasicAuth()
			if !hasAuth {
				return nil, jwt.ErrMissingLoginValues
			}
			var user User
			err := db.QueryRowx("SELECT login, password_hash FROM users WHERE login = ?", login).StructScan(&user)
			if err != nil {
				if err == sql.ErrNoRows {
					return nil, jwt.ErrFailedAuthentication
				}
				return nil, fmt.Errorf("Unexpected server database error: %s", err.Error())
			}
			err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
			if err != nil {
				return nil, jwt.ErrFailedAuthentication
			}
			return user, nil
		},
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			logger.Printf("PayloadFunc: %#v\n", data)
			if v, ok := data.(User); ok {
				return jwt.MapClaims{
					identityKey: v.Login,
				}
			}
			return jwt.MapClaims{}
		},
		// Authorizator: default
		// Unauthorized: default
		// LoginResponse: default
		// LogoutResponse: default
		// RefreshResponse: default
		// IdentityHandler: default
		// TokenLookup: default
		// TokenHeadName: default
		// TimeFunc: default
	})
	if err != nil {
		return nil, err
	}
	return jwtMiddleware, nil
}
