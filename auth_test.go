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
	"github.com/mbivert/auth/db/sqlite"
	jwt "github.com/golang-jwt/jwt/v5"
	"encoding/base64"
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
func init2() {
	dbfn := "./db_test.sqlite"
	err := os.RemoveAll(dbfn) // won't complain if dbfn doesn't exist
	if err != nil {
		log.Fatal(err)
	}
	db, err := sqlite.New(dbfn)
	if err != nil {
		log.Fatal(err)
	}

	handler = New(db)
}

func callURL(handler http.Handler, url string, args interface{}) interface{} {
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

	var out interface{}
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
func callURLWithToken(handler http.Handler, url string, args interface{}) interface{} {
	out := callURL(handler, url, args)

	out2, ok := out.(map[string]interface{})
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
	init2()

	doTests(t, []test{
		{
			"Invalid input",
			callURL,
			[]interface{}{handler, "/signin", ""},
			[]interface{}{map[string]interface{}{
				"err" : "JSON decoding failure",
			}},
		},
		{
			"Empty hash",
			callURL,
			[]interface{}{handler, "/signin", map[string]interface{}{}},
			[]interface{}{map[string]interface{}{
				"err" : "Password too small",
			}},
		},
		{
			"Password only",
			callURL,
			[]interface{}{handler, "/signin", map[string]interface{}{
				"passwd" : "1234567890",
			}},
			[]interface{}{map[string]interface{}{
				"err" : "Name too small",
			}},
		},
		{
			"Missing email",
			callURL,
			[]interface{}{handler, "/signin", map[string]interface{}{
				"passwd" : "1234567890",
				"name"   : "abc",
			}},
			[]interface{}{map[string]interface{}{
				"err" : "Email too small",
			}},
		},

		// XXX clumsy
		{
			"Invalid email",
			callURL,
			[]interface{}{handler, "/signin", map[string]interface{}{
				"passwd" : "1234567890",
				"name"   : "abc",
				"email"  : "whatever",
			}},
			[]interface{}{map[string]interface{}{
//				"err" : "Invalid email address",
				"err" : "JSON decoding failure",
			}},
		},
		{
			"Valid password/name/email",
			callURL,
			[]interface{}{handler, "/signin", map[string]interface{}{
				"passwd" : "1234567890",
				"name"   : "abc",
				"email"  : "a@b",
			}},
			[]interface{}{map[string]interface{}{
			}},
		},
		{
			"Existing email address",
			callURL,
			[]interface{}{handler, "/signin", map[string]interface{}{
				"passwd" : "1234567890",
				"name"   : "abc",
				"email"  : "a@b",
			}},
			[]interface{}{map[string]interface{}{
				"err"    : "Email already used",
			}},
		},
		{
			"Existing username",
			callURL,
			[]interface{}{handler, "/signin", map[string]interface{}{
				"passwd" : "1234567890",
				"name"   : "abc",
				"email"  : "a@bc",
			}},
			[]interface{}{map[string]interface{}{
				"err"    : "Username already used",
			}},
		},

		// TODO: to be continued once verification is implemented
	})
}

func TestLoginLogout(t *testing.T) {
	init2()

	doTests(t, []test{
		{
			"Invalid input",
			callURL,
			[]interface{}{handler, "/login", ""},
			[]interface{}{map[string]interface{}{
				"err" : "JSON decoding failure",
			}},
		},
		{
			"Invalid login",
			callURL,
			[]interface{}{handler, "/login", map[string]interface{}{
				"login"  : "whatever",
			}},
			[]interface{}{map[string]interface{}{
				"err" : "Invalid login or password",
			}},
		},
		{
			"Register account to later use for login",
			callURL,
			[]interface{}{handler, "/signin", map[string]interface{}{
				"passwd" : "1234567890",
				"name"   : "test",
				"email"  : "test@test.com",
			}},
			[]interface{}{map[string]interface{}{
			}},
		},
		{
			"Valid user, no password",
			callURL,
			[]interface{}{handler, "/login", map[string]interface{}{
				"login"  : "test",
			}},
			[]interface{}{map[string]interface{}{
				"err" : "Invalid login or password",
			}},
		},
		{
			"Logging out a logged out user",
			callURL,
			[]interface{}{handler, "/logout", map[string]interface{}{
				// Dummy, but correctly formatted/encrypted
				"token"  : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"+
					".eyJkYXRlIjoxNjc5NzkzMDM4LCJuYW1lIjoidGVzdCIs"+
					"InVuaXEiOiJqRmdOZGFldzZYNTVaRjJoc3JDdFM2NVNIdU"+
					"1DajFoakszd2VhUTJnaWVzV1NUdzJKZnNzRnpDc0pHYmp4UUtjIn0"+
					".iVU2Q99JAbuAM-dZQS2w5eP5y3MmKDC7Qwj3Z7CWbWk",
			}},
			[]interface{}{map[string]interface{}{
				"err" : "Not connected!",
			}},
		},
		{
			"Valid user/password",
			callURLWithToken,
			[]interface{}{handler, "/login", map[string]interface{}{
				"login"  : "test",
				"passwd" : "1234567890",
			}},
			[]interface{}{map[string]interface{}{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"name" : "test",
				},
			}},
		},
	})
	doTests(t, []test{
		{
			"Logging out a logged in user",
			callURL,
			[]interface{}{handler, "/logout", map[string]interface{}{
				// This is arbitrary, but signed
				"token"  : tokenStr,
			}},
			[]interface{}{map[string]interface{}{
			}},
		},
	})
}

func TestSignout(t *testing.T) {
	init2()

	doTests(t, []test{
		{
			"Invalid input",
			callURL,
			[]interface{}{handler, "/signout", ""},
			[]interface{}{map[string]interface{}{
				"err" : "JSON decoding failure",
			}},
		},
		{
			"Invalid token",
			callURL,
			[]interface{}{handler, "/signout", map[string]interface{}{
				"token"  : "whatever",
			}},
			[]interface{}{map[string]interface{}{
				"err" : errSegment,
			}},
		},
		{
			"Register account to later use for login",
			callURL,
			[]interface{}{handler, "/signin", map[string]interface{}{
				"passwd" : "1234567890",
				"name"   : "test",
				"email"  : "test@test.com",
			}},
			[]interface{}{map[string]interface{}{
			}},
		},
		{
			"Valid user/password",
			callURLWithToken,
			[]interface{}{handler, "/login", map[string]interface{}{
				"login"  : "test",
				"passwd" : "1234567890",
			}},
			[]interface{}{map[string]interface{}{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"name" : "test",
				},
			}},
		},
	})

	// Must be declared after tokenStr has been set
	doTests(t, []test{
		{
			"Valid user/token (correct signout)",
			callURL,
			[]interface{}{handler, "/signout", map[string]interface{}{
				"token"  : tokenStr,
			}},
			[]interface{}{map[string]interface{}{
			}},
		},
		{
			"Valid user/password, but deleted user",
			callURL,
			[]interface{}{handler, "/login", map[string]interface{}{
				"login"  : "test",
				"passwd" : "1234567890",
			}},
			[]interface{}{map[string]interface{}{
				"err" : "Invalid login or password",
			}},
		},
	})
}

func TestChain(t *testing.T) {
	init2()

	doTests(t, []test{
		{
			"Invalid input",
			callURL,
			[]interface{}{handler, "/chain", ""},
			[]interface{}{map[string]interface{}{
				"err" : "JSON decoding failure",
			}},
		},
		{
			"Invalid token",
			callURL,
			[]interface{}{handler, "/chain", map[string]interface{}{
				"token"  : "whatever",
			}},
			[]interface{}{map[string]interface{}{
				"err" : errSegment,
			}},
		},
		{
			"Register account to later use for login",
			callURL,
			[]interface{}{handler, "/signin", map[string]interface{}{
				"passwd" : "1234567890",
				"name"   : "test",
				"email"  : "test@test.com",
			}},
			[]interface{}{map[string]interface{}{
			}},
		},
		{
			"Valid user/password",
			callURLWithToken,
			[]interface{}{handler, "/login", map[string]interface{}{
				"login"  : "test",
				"passwd" : "1234567890",
			}},
			[]interface{}{map[string]interface{}{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"name" : "test",
				},
			}},
		},
	})

	// Must be declared after tokenStr has been set
	doTests(t, []test{
		{
			"Valid token",
			callURLWithToken,
			[]interface{}{handler, "/chain", map[string]interface{}{
				"token"  : tokenStr,
			}},
			[]interface{}{map[string]interface{}{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"name" : "test",
				},
			}},
		},
	})

	// Must be declared after tokenStr has been set
	doTests(t, []test{
		{
			"Valid token (bis)",
			callURLWithToken,
			[]interface{}{handler, "/chain", map[string]interface{}{
				"token"  : tokenStr,
			}},
			[]interface{}{map[string]interface{}{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"name" : "test",
				},
			}},
		},
	})
}

// Ensure jwt lib signing does work as expected
func TestTweaking(t *testing.T) {
	init2()

	doTests(t, []test{
		{
			"Register account to later use for login",
			callURL,
			[]interface{}{handler, "/signin", map[string]interface{}{
				"passwd" : "1234567890",
				"name"   : "test",
				"email"  : "test@test.com",
			}},
			[]interface{}{map[string]interface{}{
			}},
		},
		{
			"Valid user/password",
			callURLWithToken,
			[]interface{}{handler, "/login", map[string]interface{}{
				"login"  : "test",
				"passwd" : "1234567890",
			}},
			[]interface{}{map[string]interface{}{
				"token" : jwt.MapClaims{
					"date" : 0,          // redacted to ease tests
					"uniq" : "redacted", // idem
					"name" : "test",
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
	doTests(t, []test{
		{
			"Valid token",
			callURL,
			[]interface{}{handler, "/chain", map[string]interface{}{
				"token"  : tokenStr,
			}},
			[]interface{}{map[string]interface{}{
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
