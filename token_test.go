package auth

/*
 * Things are a bit clumsy here because we try to have
 * control over the date and the one time value.
 *
 * Things are tested with a little more finesse in auth_test.go.
 */

import (
	"testing"
	"time"
	"log"
	jwt "github.com/golang-jwt/jwt/v5"
)

func init() {
	LoadConf("config.json.base")
}

func newParseToken(name string, date int64, uniq string) jwt.MapClaims {
	str, err := newToken(name, date, uniq)
	if err != nil {
		log.Fatal(err)
	}
	claims, err := parseToken(str)
	if err != nil {
		log.Fatal(err)
	}
	return claims
}

func TestNewParseToken(t *testing.T) {
	date := time.Now().Unix()

	doTests(t, []test{
		{
			"token creation",
			newParseToken,
			[]interface{}{"username", date, "one-time-value"},
			[]interface{}{jwt.MapClaims{
				"name" : "username",
				"uniq" : "one-time-value",
				"date" : float64(date),
			}},
		},
	})
}

func newChainParseToken(
	name string, before, after int64, uniq, uniq2 string,
) jwt.MapClaims {
	storeUniq(name, uniq)
	str, err := newToken(name, before, uniq)
	if err != nil {
		log.Fatal(err)
	}

	str2, err := chainToken(str, after, uniq2)
	if err != nil {
		log.Fatal(err)
	}

	claims, err := parseToken(str2)
	if err != nil {
		log.Fatal(err)
	}

	return claims
}

func TestCheckToken(t *testing.T) {
	before := time.Now().Unix() + C.Timeout
	after  := time.Now().Unix() + 2*C.Timeout

	doTests(t, []test{
		{
			"basic token chaining",
			newChainParseToken,
			[]interface{}{
				"username", before, after,
				"one-time-value",
				"another-one-time-value",
			},
			[]interface{}{jwt.MapClaims{
				"name" : "username",
				"uniq" : "another-one-time-value",
				"date" : float64(after),
			}},
		},
	})
}