package main

import "fmt"

type TokenType string

const (
	AccessToken  TokenType = "AccessToken"
	RefreshToken TokenType = "RefreshToken"
)

// User represents row from the table "users".
type User struct {
	Login        string
	PasswordHash string `db:"password_hash"`
	AccessToken  string `db:"access_token"`
	RefreshToken string `db:"refresh_token"`
}

// userGetPasswordHash fetches user from db by login and returns its password hash.
func userGetPasswordHash(login string) (string, error) {
	var passwordHash string
	err := db.QueryRowx("SELECT password_hash FROM users WHERE login = ?", login).Scan(&passwordHash)
	if err != nil {
		return "", err
	}
	return passwordHash, nil
}

// userSaveTokens saves tokens into database.
func userSaveTokens(login, accessToken, refreshToken string) error {
	_, err := db.NamedExec("UPDATE users SET access_token=:access_token, refresh_token=:refresh_token WHERE login=:login", User{
		Login:        login,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
	if err != nil {
		return err
	}
	return nil
}

// userGetToken fetches token of given type owned by user with given login.
func userGetToken(login string, tokenType TokenType) (string, error) {
	var token string
	var err error

	switch tokenType {
	case AccessToken:
		err = db.QueryRowx("SELECT access_token FROM users WHERE login = ?", login).Scan(&token)
	case RefreshToken:
		err = db.QueryRowx("SELECT refresh_token FROM users WHERE login = ?", login).Scan(&token)
	default:
		err = fmt.Errorf("wrong token type: %s", tokenType)
	}

	if err != nil {
		return "", err
	}
	return token, nil
}

// userClearTokens clears user tokens out of database.
func userClearTokens(login string) error {
	_, err := db.NamedExec("UPDATE users SET access_token='', refresh_token='' WHERE login = :login", User{Login: login})
	if err != nil {
		return err
	}
	return nil
}
