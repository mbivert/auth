package auth

// Thin wrapper above https://github.com/golang-jwt/jwt
// to isolate technical details.
//
// "Public" functions are the capitalized ones (NewToken(),
// IsValidToken(), ChainToken(), ClearUser())

import (
	"fmt"
	"time"
	jwt "github.com/golang-jwt/jwt/v5"
	"sync"
	"crypto/subtle"
)

var (
	uniqs   = map[string]string{}
	uniqsMu = &sync.Mutex{}
)

func newHMACToken(name string, edate int64, uniq string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name" : name,
		"uniq" : uniq,
		// XXX jwt.NewNumericDate(time.Now().Add(C.Timeout)) ?
		"date" : edate,
	}).SignedString([]byte(C.HMAC))
}

func newECDSAToken(name string, edate int64, uniq string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"name" : name,
		"uniq" : uniq,
		// XXX jwt.NewNumericDate(time.Now().Add(C.Timeout)) ?
		"date" : edate,
	}).SignedString(privateKey)
}

// for tests
func newToken(name string, edate int64, uniq string) (string, error) {
	if C.HMAC != "" {
		return newHMACToken(name, edate, uniq)
	}
	return newECDSAToken(name, edate, uniq)
}

func storeUniq(name, uniq string) string {
	uniqsMu.Lock()
	defer uniqsMu.Unlock()
	uniqs[name] = uniq
	return uniq
}

func mkUniq(name string) string {
	return storeUniq(name, randString(C.LenUniq))
}

func NewToken(name string) (string, error) {
	return newToken(name, time.Now().Unix()+C.Timeout, mkUniq(name))
}

func parseHMAC(tok *jwt.Token) (interface{}, error) {
	if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Invalid signing method: %v", tok.Header["alg"])
	}
	return []byte(C.HMAC), nil
}

func parseECDSA(tok *jwt.Token) (interface{}, error) {
	if _, ok := tok.Method.(*jwt.SigningMethodECDSA); !ok {
		return nil, fmt.Errorf("Invalid signing method: %v", tok.Header["alg"])
	}
	return publicKey, nil
}

func parseToken(str string) (jwt.MapClaims, error) {
	tok, err := jwt.Parse(str, func(tok *jwt.Token) (interface{}, error) {
		if C.HMAC != ""{
			return parseHMAC(tok)
		}
		return parseECDSA(tok)
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
	// we're unpacking a (correctly) signed token: all
	// those must be present (well, can't have been
	// altered from outside at least).
	d, _ := claims["date"].(float64)
	u, _ := claims["uniq"].(string)
	n, _ := claims["name"].(string)

	uniqsMu.Lock()
	defer uniqsMu.Unlock()

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
	return chainToken(str, time.Now().Unix()+C.Timeout, "")
}

func ClearUser(name string) {
	uniqsMu.Lock()
	defer uniqsMu.Unlock()
	delete(uniqs, name)
}
