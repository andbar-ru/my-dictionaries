package main

import (
	"encoding/json"
	"os"
)

// Config stores app configuration.
type Config struct {
	ListenAddress string     `json:"listenAddress"`
	DatabasePath  string     `json:"databasePath"`
	LogConfig     *LogConfig `json:"log"`
	JWTConfig     *JWTConfig `json:"jwt"`
}

// LogConfig stores log configuration.
type LogConfig struct {
	Files []string `json:"files"`
	Level string   `json:"level"`
}

// JWTConfig stores JWT configuration.
type JWTConfig struct {
	Subject            string `json:"subject"`
	AccessKey          string `json:"accessKey"`
	RefreshKey         string `json:"refreshKey"`
	AccessKeyLifetime  int    `json:"accessKeyLifetime"`
	RefreshKeyLifeTime int    `json:"refreshKeyLifeTime"`
}

// GetConfig reads config file and decodes it into Config.
func GetConfig() *Config {
	configPath := os.Getenv("MY_DICTIONARIES_CONFIG")
	if configPath == "" {
		configPath = "config.json"
	}
	file, err := os.Open(configPath)
	checkErr(err)
	defer closeCheck(file)

	decoder := json.NewDecoder(file)
	var config Config
	err = decoder.Decode(&config)
	checkErr(err)
	return &config
}
