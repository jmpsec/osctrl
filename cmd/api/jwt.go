package main

import (
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/spf13/viper"
)

type tokenClaims struct {
	Username string `json:"username"`
	Level    string `json:"level"`
	jwt.StandardClaims
}

func createToken(username, level string, expireDays int) (string, error) {
	expirationTime := time.Now().Add(time.Hour * 24 * time.Duration(expireDays))
	// Create the JWT claims, which includes the username, level and expiry time
	claims := &tokenClaims{
		Username: username,
		Level:    level,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}
	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtConfig.JWTSecret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// Function to load the configuration file
func loadJWTConfiguration(file string) (types.JSONConfigurationJWT, error) {
	var cfg types.JSONConfigurationJWT
	log.Printf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	err := viper.ReadInConfig()
	if err != nil {
		return cfg, err
	}
	// JWT values
	headersRaw := viper.Sub(settings.AuthJWT)
	err = headersRaw.Unmarshal(&cfg)
	if err != nil {
		return cfg, err
	}

	// No errors!
	return cfg, nil
}
