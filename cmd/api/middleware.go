package main

import (
	"errors"
	"github.com/pascaldekloe/jwt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (app *application) enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		next.ServeHTTP(w, r)
	})
}

func (app *application) checkToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Authorization")

		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			// Could set anonymous user
		}

		headerParts := strings.Split(authHeader, " ")
		if len(headerParts) != 2 {
			app.errorJSON(w, errors.New("invalid authorization header"))
			return
		}
		if headerParts[0] != "Bearer" {
			app.errorJSON(w, errors.New("unauthorized - no bearer"))
			return
		}
		token := headerParts[1]

		claims, err := jwt.HMACCheck([]byte(token), []byte(app.config.jwt.secret))
		if err != nil {
			app.errorJSON(w, errors.New("unauthorized - failed HMAC check"))
			return
		}
		if !claims.Valid(time.Now()) {
			app.errorJSON(w, errors.New("unauthorized - token expired"))
			return
		}
		if !claims.AcceptAudience("mydomain.com") {
			app.errorJSON(w, errors.New("unauthorized - invalid audience"))
			return
		}
		if claims.Issuer != "mydomain.com" {
			app.errorJSON(w, errors.New("unauthorized - invalid issuer"))
			return
		}
		userID, err := strconv.ParseInt(claims.Subject, 10, 64)
		if err != nil {
			app.errorJSON(w, errors.New("unauthorized"))
			return
		}
		log.Println("Valid user: ", userID)
		next.ServeHTTP(w, r)
	})
}
