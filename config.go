package auth

// TODO: to be tested; in particular, the errors from LoadConf

import (
	"encoding/json"
	"io/ioutil"
	"crypto/ecdsa"
	jwt "github.com/golang-jwt/jwt/v5"
	"fmt"
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

func LoadKeys() error {
	pub, err := ioutil.ReadFile(C.PublicKey)
	if err != nil {
		return fmt.Errorf("Cannot load public key: %s", err)
	}

	priv, err := ioutil.ReadFile(C.PrivateKey)
	if err != nil {
		return fmt.Errorf("Cannot load private key: %s", err)
	}

	// For clarity (but also used to check which one to use)
	C.HMAC = ""

	privateKey, err = jwt.ParseECPrivateKeyFromPEM(priv)
	if err != nil {
		return fmt.Errorf("Private key (.pem) parsing error: %s", err)
	}

	publicKey, err = jwt.ParseECPublicKeyFromPEM(pub)
	if err != nil {
		return fmt.Errorf("Public key parsing error: %s", err)
	}

	return nil
}

func LoadConf(fn string) error {
	x, err := ioutil.ReadFile(fn)
	if err != nil {
		return fmt.Errorf("Cannot read configuration file: %s", err)
	}

	if err := json.Unmarshal(x, &C); err != nil {
		return fmt.Errorf("Error while parsing configuration file: %s", err)
	}

	if C.PrivateKey != "" {
		if err := LoadKeys(); err != nil {
			return err
		}
	}

	if C.HMAC == "" && C.PrivateKey == "" {
		return fmt.Errorf("At least a HMAC or a PrivateKey must be specified")
	}

	// XXX we may even want to not allow below a certain threshold here
	if C.LenUniq == 0 {
		return fmt.Errorf("LenUniq unconfigured ?")
	}

	// No further checking:
	//	Wrong configuration => undefined behavior.
	return nil
}
