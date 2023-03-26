package auth

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"crypto/ecdsa"
	jwt "github.com/golang-jwt/jwt/v5"
)

type Config struct {
	// TODO
	HMAC		string
	PublicKey   string
	PrivateKey  string

	SMTPServer string
	SMTPPort   string
	AuthEmail  string
	AuthPasswd string

	Timeout  int64
	LenUniq  int
}

var C Config
var publicKey  *ecdsa.PublicKey
var privateKey *ecdsa.PrivateKey

func LoadKeys() {
	pub, err := ioutil.ReadFile(C.PublicKey)
	if err != nil {
		log.Fatal("Cannot load public key", err)
	}

	priv, err := ioutil.ReadFile(C.PrivateKey)
	if err != nil {
		log.Fatal("Cannot load private key", err)
	}

	// For clarity (but also used to check which one to use)
	C.HMAC = ""

	privateKey, err = jwt.ParseECPrivateKeyFromPEM(priv)
	if err != nil {
		log.Fatal("Private key (.pem) parsing error", err)
	}

	publicKey, err = jwt.ParseECPublicKeyFromPEM(pub)
	if err != nil {
		log.Fatal("Public key parsing error", err)
	}
}

func LoadConf(fn string) {
	x, err := ioutil.ReadFile(fn)
	if err != nil {
		log.Fatal("Cannot read configuration file: ", err)
	}

	if err := json.Unmarshal(x, &C); err != nil {
		log.Fatal("Error while parsing configuration file: ", err)
	}

	if C.PrivateKey != "" {
		LoadKeys()
	}

	// No further checking:
	//	Wrong configuration => undefined behavior.
}
