package auth

// Thin wrapper above https://github.com/golang-jwt/jwt
// to isolate technical details.
//
// "Public" functions are the capitalized ones (NewToken(),
// CheckToken(), ChainToken(), ClearUser())

import (
	"fmt"
	"time"
	jwt "github.com/golang-jwt/jwt/v5"
	"sync"
	"crypto/subtle"
)

var (
	uniqs   = map[UserId]string{}
	uniqsMu = &sync.Mutex{}
)

func newHMACToken(uid UserId, edate int64, uniq string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid"  : uid,
		"uniq" : uniq,
		// XXX jwt.NewNumericDate(time.Now().Add(C.Timeout)) ?
		"date" : edate,
	}).SignedString([]byte(C.HMAC))
}

func newECDSAToken(uid UserId, edate int64, uniq string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"uid"  : uid,
		"uniq" : uniq,
		// XXX jwt.NewNumericDate(time.Now().Add(C.Timeout)) ?
		"date" : edate,
	}).SignedString(privateKey)
}

// NOTE: not inlined in NewToken for tests
func newToken(uid UserId, edate int64, uniq string) (string, error) {
	if C.HMAC != "" {
		return newHMACToken(uid, edate, uniq)
	}
	return newECDSAToken(uid, edate, uniq)
}

func storeUniq(uid UserId, uniq string) string {
	uniqsMu.Lock()
	defer uniqsMu.Unlock()
	uniqs[uid] = uniq
	return uniq
}

func mkUniq(uid UserId) string {
	return storeUniq(uid, randString(C.LenUniq))
}

func NewToken(uid UserId) (string, error) {
	return newToken(uid, time.Now().Unix()+C.Timeout, mkUniq(uid))
}

func parseHMAC(tok *jwt.Token) (any, error) {
	if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Invalid signing method: %v", tok.Header["alg"])
	}
	return []byte(C.HMAC), nil
}

func parseECDSA(tok *jwt.Token) (any, error) {
	if _, ok := tok.Method.(*jwt.SigningMethodECDSA); !ok {
		return nil, fmt.Errorf("Invalid signing method: %v", tok.Header["alg"])
	}
	return publicKey, nil
}

func ParseToken(str string) (jwt.MapClaims, error) {
	tok, err := jwt.Parse(str, func(tok *jwt.Token) (any, error) {
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

func checkToken(claims jwt.MapClaims) bool {
	uniqsMu.Lock()
	defer uniqsMu.Unlock()

	// we're unpacking a (correctly) signed token: all
	// those must be present (well, can't have been
	// altered from outside at least).
	//
	// NOTE: we may still want to add assertions here anyway.
	date, _ := claims["date"].(float64)
	uniq, _ := claims["uniq"].(string)
	xuid, _ := claims["uid"].(float64)

	uid := UserId(xuid)

	dok := (int64(date) > time.Now().Unix())

	// XXX/TODO
	// I mean, sure, but if the token has been signed and we're assuming
	// it hasn't been altered, the likelihood for this to be incorrect
	// is zero: the whole uniq shebang feels overkill, especially
	// with all that surrounding noise.
	uok := subtle.ConstantTimeCompare([]byte(uniq), []byte(uniqs[uid])) == 1

	return dok && uok
}

func CheckToken(str string) (bool, UserId, error) {
	// TODO: test & document (essentially, we're going to
	// rely on a HTTP cookie to store the token, and the way
	// it's removed is by setting it to the empty string)
	if str == "" {
		return false, -1, nil
	}
	claims, err := ParseToken(str)
	if err != nil {
		return false, -1, err
	}

	xuid, _ := claims["uid"].(float64)
	uid := UserId(xuid)

	return checkToken(claims), uid, nil
}

// NOTE: Again, not inlined in ChainToken() for tests
func chainToken(str string, edate int64, uniq string) (string, error) {
	claims, err := ParseToken(str)
	if err != nil {
		return "", err
	}

	if !checkToken(claims) {
		return "", fmt.Errorf("Expired token")
	}

	xuid, _ := claims["uid"].(float64)
	uid := UserId(xuid)

	// In tests, we provide a known uniq; it's "" iff we're
	// in production (see ChainToken() below)
	if uniq == "" {
		uniq = mkUniq(uid)
	}

	return newToken(uid, edate, uniq)
}

func ChainToken(str string) (string, error) {
	return chainToken(str, time.Now().Unix()+C.Timeout, "")
}

func ClearUser(uid UserId) {
	uniqsMu.Lock()
	defer uniqsMu.Unlock()
	delete(uniqs, uid)
}
