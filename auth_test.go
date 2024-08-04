package auth

/*
	TODO: edit tests framework article (why?)
*/

import (
	"testing"
	"log"
	"net/http"
	"encoding/json"
	"strings"
	"os"
//	"io/ioutil"
	"net/http/httptest"
	jwt "github.com/golang-jwt/jwt/v5"
	"encoding/base64"
	"github.com/mbivert/ftests"
)

var handler http.Handler

// ease lib update
var errSegment = jwt.ErrTokenMalformed.Error()+": token contains an invalid number of segments"
var errSignature = jwt.ErrTokenSignatureInvalid.Error()+": signature is invalid"

func init() {
	if err := LoadConf("config.json.base"); err != nil {
		log.Fatal(err)
	}
}

// Individual tests rely on a ~fresh DB; "init()" cannot be
// called directly.
func initauthtest() {
	dbfn := "./db_test.sqlite"
	err := os.RemoveAll(dbfn) // won't complain if dbfn doesn't exist
	if err != nil {
		log.Fatal(err)
	}
	db, err := NewSQLite(dbfn)
	if err != nil {
		log.Fatal(err)
	}

	// XXX s/New/NewAuth/ ?
	handler = New(db)

	// XXX/NOTE: for now, all tests require verification to be disabled.
	C.NoVerif = true
}

func getVerifTokFor(uid UserId) string {
	verifsMu.Lock()
	defer verifsMu.Unlock()
	for k, v := range verifs {
		if v == uid {
			return k
		}
	}
	return ""
}

func callURL(handler http.Handler, url string, args any) any {
	ts := httptest.NewServer(handler)
	defer ts.Close()

	sargs, err := json.MarshalIndent(args, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	r, err := http.Post(ts.URL+url, "application/json", strings.NewReader(string(sargs)))
	if err != nil {
		log.Fatal(err)
	}

	var out any
//	x, err := ioutil.ReadAll(r.Body)
//	fmt.Println(string(x))
	err = json.NewDecoder(r.Body).Decode(&out)
//	err = json.Unmarshal(x, &out)
	if err != nil {
		log.Fatal(err)
	}

	r.Body.Close()

	return out
}

// shared token set by callURLWithToken,
// so that we can re-use it for later queries
var tokenStr = ""

// same as callURL, but output is expected to be a hash containing
// a token
func callURLWithToken(handler http.Handler, url string, args any) any {
	out := callURL(handler, url, args)

	out2, ok := out.(map[string]any)
	if !ok {
		log.Fatal("Weird output")
	}

	xstr, ok := out2["token"]
	if !ok {
		log.Fatal("No token found! (", out2["err"], ")")
	}

	tokenStr, ok = xstr.(string)
	if !ok {
		log.Fatal("Token is not a string")
	}

	tok, err := parseToken(tokenStr)
	if err != nil {
		log.Fatal("Failed to parse token")
	}

	if _, ok := tok["date"]; !ok {
		log.Fatal("No date!")
	}

	tok["date"] = 0
	tok["uniq"] = "redacted"

	out2["token"] = tok

	return out2
}

func TestSignin(t *testing.T) {
	initauthtest()

	ftests.Run(t, []ftests.Test{
		{
			"Invalid input",
			callURL,
			[]any{handler, "/signin", ""},
			[]any{map[string]any{
				"err" : "JSON decoding failure",
			}},
		},
		{
			"Empty hash",
			callURL,
			[]any{handler, "/signin", map[string]any{}},
			[]any{map[string]any{
				"err" : "Password too small",
			}},
		},
		{
			"Password only",
			callURL,
			[]any{handler, "/signin", map[string]any{
				"passwd" : "1234567890",
			}},
			[]any{map[string]any{
				"err" : "Name too small",
			}},
		},
		{
			"Missing email",
			callURL,
			[]any{handler, "/signin", map[string]any{
				"passwd" : "1234567890",
				"name"   : "abc",
			}},
			[]any{map[string]any{
				"err" : "Email too small",
			}},
		},

		// XXX clumsy
		{
			"Invalid email",
			callURL,
			[]any{handler, "/signin", map[string]any{
				"passwd" : "1234567890",
				"name"   : "abc",
				"email"  : "whatever",
			}},
			[]any{map[string]any{
//				"err" : "Invalid email address",
				"err" : "JSON decoding failure",
			}},
		},
		// Assuming NoVerif = true here
		{
			"Valid password/name/email",
			callURLWithToken,
			[]any{handler, "/signin", map[string]any{
				"passwd" : "1234567890",
				"name"   : "abc",
				"email"  : "a@b",
			}},
			[]any{map[string]any{
				"token" : jwt.MapClaims{
					"date"  : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"uid"  : float64(1), // fragile?
				},
			}},
		},
		{
			"Existing email address",
			callURL,
			[]any{handler, "/signin", map[string]any{
				"passwd" : "1234567890",
				"name"   : "abc",
				"email"  : "a@b",
			}},
			[]any{map[string]any{
				"err"    : "Email already used",
			}},
		},
		{
			"Existing username",
			callURL,
			[]any{handler, "/signin", map[string]any{
				"passwd" : "1234567890",
				"name"   : "abc",
				"email"  : "a@bc",
			}},
			[]any{map[string]any{
				"err"    : "Username already used",
			}},
		},

		// TODO: to be continued once verification is implemented
	})
}

func TestLoginLogout(t *testing.T) {
	initauthtest()

	ftests.Run(t, []ftests.Test{
		{
			"Invalid input",
			callURL,
			[]any{handler, "/login", ""},
			[]any{map[string]any{
				"err" : "JSON decoding failure",
			}},
		},
		{
			"Invalid login",
			callURL,
			[]any{handler, "/login", map[string]any{
				"login"  : "whatever",
			}},
			[]any{map[string]any{
				"err" : "Invalid username or email",
			}},
		},
		// Assuming NoVerif = true here
		{
			"Register account to later use for login",
			callURLWithToken,
			[]any{handler, "/signin", map[string]any{
				"passwd" : "1234567890",
				"name"   : "test",
				"email"  : "test@test.com",
			}},
			[]any{map[string]any{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"uid"  : float64(1),
				},
			}},
		},
		{
			"Valid user, no password, no verified email",
			callURL,
			[]any{handler, "/login", map[string]any{
				"login"  : "test",
			}},
			[]any{map[string]any{
				"err" : "Invalid login or password",
			}},
		},
		{
			"Logging out a logged out user",
			callURL,
			[]any{handler, "/logout", map[string]any{
				// Dummy, but correctly formatted/encrypted
				"token"  : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"+
					".eyJkYXRlIjoxNjc5NzkzMDM4LCJuYW1lIjoidGVzdCIs"+
					"InVuaXEiOiJqRmdOZGFldzZYNTVaRjJoc3JDdFM2NVNIdU"+
					"1DajFoakszd2VhUTJnaWVzV1NUdzJKZnNzRnpDc0pHYmp4UUtjIn0"+
					".iVU2Q99JAbuAM-dZQS2w5eP5y3MmKDC7Qwj3Z7CWbWk",
			}},
			[]any{map[string]any{
				"err" : "Not connected!",
			}},
		},
		{
			"Valid user/password",
			callURLWithToken,
			[]any{handler, "/login", map[string]any{
				"login"  : "test",
				"passwd" : "1234567890",
			}},
			[]any{map[string]any{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"uid"  : float64(1),
				},
			}},
		},
	})
	ftests.Run(t, []ftests.Test{
		{
			"Logging out a logged in user",
			callURL,
			[]any{handler, "/logout", map[string]any{
				// This is arbitrary, but signed
				"token"  : tokenStr,
			}},
			[]any{map[string]any{
			}},
		},
	})
}

func TestSignout(t *testing.T) {
	initauthtest()

	ftests.Run(t, []ftests.Test{
		{
			"Invalid input",
			callURL,
			[]any{handler, "/signout", ""},
			[]any{map[string]any{
				"err" : "JSON decoding failure",
			}},
		},
		{
			"Invalid token",
			callURL,
			[]any{handler, "/signout", map[string]any{
				"token"  : "whatever",
			}},
			[]any{map[string]any{
				"err" : errSegment,
			}},
		},
		{
			"Register account to later use for login",
			callURLWithToken,
			[]any{handler, "/signin", map[string]any{
				"passwd" : "1234567890",
				"name"   : "test",
				"email"  : "test@test.com",
			}},
			[]any{map[string]any{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"uid"  : float64(1),
				},
			}},
		},
		{
			"Valid user/password",
			callURLWithToken,
			[]any{handler, "/login", map[string]any{
				"login"  : "test",
				"passwd" : "1234567890",
			}},
			[]any{map[string]any{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"uid"  : float64(1),
				},
			}},
		},
	})

	// Must be declared after tokenStr has been set
	ftests.Run(t, []ftests.Test{
		{
			"Valid user/token (correct signout)",
			callURL,
			[]any{handler, "/signout", map[string]any{
				"token"  : tokenStr,
			}},
			[]any{map[string]any{
			}},
		},
		{
			"Valid user/password, but deleted user",
			callURL,
			[]any{handler, "/login", map[string]any{
				"login"  : "test",
				"passwd" : "1234567890",
			}},
			[]any{map[string]any{
				"err" : "Invalid username or email",
			}},
		},
	})
}

func TestChain(t *testing.T) {
	initauthtest()

	ftests.Run(t, []ftests.Test{
		{
			"Invalid input",
			callURL,
			[]any{handler, "/chain", ""},
			[]any{map[string]any{
				"err" : "JSON decoding failure",
			}},
		},
		{
			"Invalid token",
			callURL,
			[]any{handler, "/chain", map[string]any{
				"token"  : "whatever",
			}},
			[]any{map[string]any{
				"err" : errSegment,
			}},
		},
		{
			"Register account to later use for login",
			callURLWithToken,
			[]any{handler, "/signin", map[string]any{
				"passwd" : "1234567890",
				"name"   : "test",
				"email"  : "test@test.com",
			}},
			[]any{map[string]any{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"uid"  : float64(1),
				},
			}},
		},
		{
			"Valid user/password",
			callURLWithToken,
			[]any{handler, "/login", map[string]any{
				"login"  : "test",
				"passwd" : "1234567890",
			}},
			[]any{map[string]any{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"uid"  : float64(1),
				},
			}},
		},
	})

	// Must be declared after tokenStr has been set
	ftests.Run(t, []ftests.Test{
		{
			"Valid token",
			callURLWithToken,
			[]any{handler, "/chain", map[string]any{
				"token"  : tokenStr,
			}},
			[]any{map[string]any{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"uid"  : float64(1),
				},
			}},
		},
	})

	// Must be declared after tokenStr has been set
	ftests.Run(t, []ftests.Test{
		{
			"Valid token (bis)",
			callURLWithToken,
			[]any{handler, "/chain", map[string]any{
				"token"  : tokenStr,
			}},
			[]any{map[string]any{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"uid"  : float64(1),
				},
			}},
		},
	})
}

// Ensure jwt lib signing does work as expected
func TestTweaking(t *testing.T) {
	initauthtest()

	ftests.Run(t, []ftests.Test{
		{
			"Register account to later use for login",
			callURLWithToken,
			[]any{handler, "/signin", map[string]any{
				"passwd" : "1234567890",
				"name"   : "test",
				"email"  : "test@test.com",
			}},
			[]any{map[string]any{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"uid"  : float64(1),
				},
			}},
		},
		{
			"Valid user/password",
			callURLWithToken,
			[]any{handler, "/login", map[string]any{
				"login"  : "test",
				"passwd" : "1234567890",
			}},
			[]any{map[string]any{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"uid"  : float64(1),
				},
			}},
		},
	})
	log.Println(tokenStr)
	xs := strings.Split(tokenStr, ".")
	xs1 := base64.RawURLEncoding.EncodeToString([]byte(
		`{"name" : "someoneelse", "date" : "random", "uniq": "maybe" }`,
	))
	tokenStr = xs[0]+"."+xs1+"."+xs[2]
	ftests.Run(t, []ftests.Test{
		{
			"Valid token",
			callURL,
			[]any{handler, "/chain", map[string]any{
				"token"  : tokenStr,
			}},
			[]any{map[string]any{
				"err" : errSignature,
			}},
		},
	})
}

// NOTE: some error messages depends on hmac/keys and
// thus have been left out (the goal is to perform a
// basic check that things work OK with private/public
// keys, so it's good enough)
func TestSomeWithECDSA(t *testing.T) {
	C.PublicKey = "public.pem"
	C.PrivateKey = "private.pem"
	hmac := C.HMAC

	LoadKeys()

	// Why not
	TestChain(t)
	TestSignin(t)
	TestSignout(t)

	C.PublicKey = ""
	C.PrivateKey = ""
	C.HMAC = hmac
}
