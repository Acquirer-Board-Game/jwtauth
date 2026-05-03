package jwtauth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	Secret []byte

	ErrMissingAuth   string
	ErrSigningMethod string
	ErrInvalidToken  string

	JWTClaimUser string
}

func (c Config) normalized() Config {
	if c.ErrMissingAuth == "" {
		c.ErrMissingAuth = "unauthorized request"
	}
	if c.ErrSigningMethod == "" {
		c.ErrSigningMethod = "invalid signing method"
	}
	if c.ErrInvalidToken == "" {
		c.ErrInvalidToken = "invalid token"
	}
	if c.JWTClaimUser == "" {
		c.JWTClaimUser = "user"
	}
	return c
}

func Middleware(cfg Config) gin.HandlerFunc {
	cfg = cfg.normalized()
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": cfg.ErrMissingAuth})
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		_, claims, err := verifyToken(tokenStr, cfg)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		raw, ok := claims[cfg.JWTClaimUser]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": cfg.ErrInvalidToken})
			return
		}
		c.Set(cfg.JWTClaimUser, raw)
		c.Next()
	}
}

func verifyToken(token string, cfg Config) (*jwt.Token, jwt.MapClaims, error) {
	cfg = cfg.normalized()
	claims := jwt.MapClaims{}
	parse, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%s", cfg.ErrSigningMethod)
		}
		return cfg.Secret, nil
	})
	if err != nil {
		return nil, nil, err
	}
	if !parse.Valid {
		return nil, nil, fmt.Errorf("%s", cfg.ErrInvalidToken)
	}
	return parse, claims, nil
}
