package auth

// Thin wrapper above https://github.com/golang-jwt/jwt
// to isolate technical details.
//
// "Public" functions are the capitalized ones (NewToken(),
// IsValidToken(), ChainToken())

import (
	"fmt"
	"time"
	jwt "github.com/golang-jwt/jwt/v5"
	"sync"
	"crypto/subtle"
	"math/rand"
)

const (
	alnum = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ123456789"
)

var (
	timeout = int64(3600)
	secret  = []byte("something-to-be-definitely-refined")
	uniqs   = map[string]string{}
	uniqsmu = &sync.Mutex{}
)

// Generate random string of n bytes
func randString(n int) string {
	buf := make([]byte, n)

	for i := 0; i < n; i++ {
		buf[i] = alnum[rand.Intn(len(alnum))]
	}

	return string(buf)
}

// for tests
func newToken(name string, edate int64, uniq string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name" : name,
		"uniq" : uniq,
		// XXX jwt.NewNumericDate(time.Now().Add(24 * time.Hour)) ?
		"date" : edate,
	}).SignedString(secret)
}

func storeUniq(name, uniq string) string {
	uniqsmu.Lock()
	uniqs[name] = uniq
	uniqsmu.Unlock()
	return uniq
}

func mkUniq(name string) string {
	// TODO configuration / parameter (length)
	return storeUniq(name, randString(64))
}

func NewToken(name string) (string, error) {
	return newToken(name, time.Now().Unix()+timeout, mkUniq(name))
}

func parseToken(str string) (jwt.MapClaims, error) {
	tok, err := jwt.Parse(str, func(tok *jwt.Token) (interface{}, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Invalid signing method: %v", tok.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := tok.Claims.(jwt.MapClaims); ok && tok.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("Invalid token (not a jwt.MapClaims?)")
}

func isValidToken(claims jwt.MapClaims) bool {
	// we're unpakcing a (correctly) signed token: all
	// those must be present (well, can't have been
	// altered from outside at least).
	d, _ := claims["date"].(float64)
	u, _ := claims["uniq"].(string)
	n, _ := claims["name"].(string)

	uniqsmu.Lock()
	defer uniqsmu.Unlock()

	dok := (int64(d) > time.Now().Unix())
	uok := subtle.ConstantTimeCompare([]byte(u), []byte(uniqs[n])) == 1

	return dok && uok
}

func IsValidToken(str string) (bool, string, error) {
	claims, err := parseToken(str)
	if err != nil {
		return false, "", err
	}

	n, _ := claims["name"].(string)

	return isValidToken(claims), n, nil
}

// for tests
func chainToken(str string, edate int64, uniq string) (string, error) {
	claims, err := parseToken(str)
	if err != nil {
		return "", err
	}

	if !isValidToken(claims) {
		return "", fmt.Errorf("Expired token")
	}

	n, _ := claims["name"].(string)

	// To ease tests
	if uniq == "" {
		uniq = mkUniq(n)
	}

	return newToken(n, edate, uniq)
}

func ChainToken(str string) (string, error) {
	return chainToken(str, time.Now().Unix()+timeout, "")
}
