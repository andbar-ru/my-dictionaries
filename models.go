package main

// User represents row from the table "users".
type User struct {
	Login        string
	PasswordHash string `db:"password_hash"`
	AccessToken  string `db:"access_token"`
	RefreshToken string `db:"refresh_token"`
}
