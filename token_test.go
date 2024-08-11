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
	"github.com/mbivert/ftests"
)

func init() {
	if err := LoadConf("config.json.base"); err != nil {
		log.Fatal(err)
	}
}

func newParseToken(uid UserId, date int64, uniq string) jwt.MapClaims {
	str, err := newToken(uid, date, uniq)
	if err != nil {
		log.Fatal(err)
	}
	claims, err := ParseToken(str)
	if err != nil {
		log.Fatal(err)
	}
	return claims
}

func TestNewParseToken(t *testing.T) {
	date := time.Now().Unix()

	ftests.Run(t, []ftests.Test{
		{
			"token creation",
			newParseToken,
			[]any{UserId(42), date, "one-time-value"},
			[]any{jwt.MapClaims{
				"uid"  : float64(42),
				"uniq" : "one-time-value",
				"date" : float64(date),
			}},
		},
	})
}

func newChainParseToken(
	uid UserId, before, after int64, uniq, uniq2 string,
) jwt.MapClaims {
	storeUniq(uid, uniq)
	str, err := newToken(uid, before, uniq)
	if err != nil {
		log.Fatal(err)
	}

	str2, err := chainToken(str, after, uniq2)
	if err != nil {
		log.Fatal(err)
	}

	claims, err := ParseToken(str2)
	if err != nil {
		log.Fatal(err)
	}

	return claims
}

func TestCheckToken(t *testing.T) {
	before := time.Now().Unix() + C.Timeout
	after  := time.Now().Unix() + 2*C.Timeout

	ftests.Run(t, []ftests.Test{
		{
			"basic token chaining",
			newChainParseToken,
			[]any{
				UserId(42), before, after,
				"one-time-value",
				"another-one-time-value",
			},
			[]any{jwt.MapClaims{
				"uid"  : float64(42),
				"uniq" : "another-one-time-value",
				"date" : float64(after),
			}},
		},
	})
}
