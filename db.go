package main

import (
	"os"

	"github.com/jmoiron/sqlx"
	// Register sqlite3.
	_ "github.com/mattn/go-sqlite3"
)

// getDB opens and returns sqlite database specified in config.
// Consumers have to close the database.
func getDB() (*sqlx.DB, error) {
	databasePath := getPath(config.DatabasePath)
	// Check if database exists.
	_, err := os.Stat(databasePath)
	if err != nil {
		return nil, err
	}
	// Open database.
	db, err := sqlx.Connect("sqlite3", databasePath)
	if err != nil {
		return nil, err
	}
	return db, nil
}
