package jwtauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func TestMiddleware_missingHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/t", Middleware(Config{Secret: []byte("s")}), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/t", nil))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_validToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := []byte("test-secret")
	token := mustSign(t, secret, "alice")

	r := gin.New()
	r.GET("/t", Middleware(Config{Secret: secret}), func(c *gin.Context) {
		v, _ := c.Get("user")
		c.String(http.StatusOK, v.(string))
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", w.Code, w.Body.String())
	}
	if w.Body.String() != "alice" {
		t.Fatalf("body = %q", w.Body.String())
	}
}

func mustSign(t *testing.T, secret []byte, user string) string {
	t.Helper()
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	s, err := claims.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
