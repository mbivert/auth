package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TODO: timeout
var verifs = map[string]UserId{}
var verifsMu sync.Mutex

func mkVerifTok(uid UserId) string {
	verifsMu.Lock()
	defer verifsMu.Unlock()
	var tok string
	for {
		// XXX another constant perhaps?
		tok = randString(C.LenUniq)
		if _, ok := verifs[tok]; !ok {
			break
		}
	}
	verifs[tok] = uid
	return tok
}

func tryVerifTok(tok string) UserId {
	verifsMu.Lock()
	defer verifsMu.Unlock()
	if uid, ok := verifs[tok]; ok {
		delete(verifs, tok)
		return uid
	}
	return -1
}

func (e *Email) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &e.string); err != nil {
		return err
	}
	if !strings.Contains(e.string, "@") {
		return fmt.Errorf("Invalid email address")
	}

	return nil
}

// internal error (500)
type intErr struct {
	string
}

func (e *intErr) Error() string {
	return e.string
}

type SomeErr struct {
	Err string `json:"err"`
}

func fails(w http.ResponseWriter, err error) {
	if _, ok := err.(*intErr); ok {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err2 := json.NewEncoder(w).Encode(&SomeErr{err.Error()})
	if err2 != nil {
		// XXX this will have to do for now
		w.Write([]byte("{ err : \"error while encoding '" +
			err.Error() + "': " + err2.Error() + "\"}"))
	}
}

// fancy
func wrap[Tin, Tout any](
	db DB, f func(db DB, in *Tin, out *Tout) error,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var in Tin
		var out Tout

		r.Body = http.MaxBytesReader(w, r.Body, 1048576)
		err := json.NewDecoder(r.Body).Decode(&in)
		if err != nil {
			log.Println(err)
			err = fmt.Errorf("JSON decoding failure")
			goto err
		}

		err = f(db, &in, &out)
		if err != nil {
			goto err
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		err = json.NewEncoder(w).Encode(out)

		if err != nil {
			log.Println(err)
			err = fmt.Errorf("JSON encoding failure")
			goto err
		}

		return

	err:
		fails(w, err)
		return
	}
}

func hash(passwd string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(passwd), bcrypt.MinCost)
	return string(h), err
}

func Signin(db DB, in *SigninIn, out *SigninOut) error {
	// encoding/json (just) manages basic JSON parsing, it's
	// a bit simpler to do things here rather than extend
	// the decoder up there
	//
	// Perhaps we'd want to have the full email check here too
	// (the current error is clumsy "JSON parsing error" or so)
	if len(in.Passwd) < 10 {
		return fmt.Errorf("Password too small")
	}
	if len(in.Name) < 3 {
		return fmt.Errorf("Name too small")
	}
	if len(in.Email.string) < 3 {
		return fmt.Errorf("Email too small")
	}

	var err error
	in.Passwd, err = hash(in.Passwd)
	if err != nil {
		return err
	}

	// XXX rough/verbose error message
	u := User{
		0, in.Name, in.Email.string, in.Passwd, false, time.Now().UTC().Unix(),
	}
	if err := db.AddUser(&u); err != nil {
		return err
	}

	if C.NoVerif {
		out.Token, err = NewToken(u.Id)
		return err
	}

	tok := mkVerifTok(u.Id)

	// TODO: send an email to the specified address.
	// If so, we'll want to add a timer/restrictions to avoid
	// being used to spam people. (e.g. allow n /signin per 24h at most)
	fmt.Println(tok)

	// TODO: also, have a way to automatically remove
	// unverified accounts periodically.

	// (for later)

	return nil
}

func Login(db DB, in *LoginIn, out *LoginOut) error {
	var u User
	u.Name = in.Login
	u.Email = in.Login
	if err := db.GetUser(&u); err != nil {
		return err
	}

	if !C.NoVerif && !u.Verified {
		return fmt.Errorf("Email not verified")
	}

	// constant time
	err := bcrypt.CompareHashAndPassword([]byte(u.Passwd), []byte(in.Passwd))
	if err == nil {
		out.Token, err = NewToken(u.Id)
		return err
	}

	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return fmt.Errorf("Invalid login or password")
	}

	return &intErr{err.Error()}
}

func Signout(db DB, in *SignoutIn, out *SignoutOut) error {
	ok, uid, err := IsValidToken(in.Token)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Not connected!")
	}

	// TODO: maybe send a confirmation email
	_, err = db.RmUser(uid)

	return err
}

func Chain(db DB, in *ChainIn, out *ChainOut) (err error) {
	out.Token, err = ChainToken(in.Token)
	return err
}

func Check(db DB, in *CheckIn, out *CheckOut) (err error) {
	out.Match, _, err = IsValidToken(in.Token)
	return err
}

func Logout(db DB, in *LogoutIn, out *LogoutOut) error {
	ok, uid, err := IsValidToken(in.Token)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Not connected!")
	}

	ClearUser(uid)
	return nil
}

func Edit(db DB, in *EditIn, out *EditOut) (err error) {
	out.Token, err = ChainToken(in.Token)
	if err != nil {
		return err
	}

	// Don't chain & fetch data from db?
	//
	// Then if newpasswd exists is > 10 and
	// so forth, update the password.
	//
	// Finally, as we'll had fetch User from
	// db, we'll be able to determine whether
	// email has changed, and if so, it should
	// be valid as the JSON has checked it,
	// and we just need to make sure it doesn't
	// exists in database.

	return nil
}

func Verify(db DB, in *VerifyIn, out *VerifyOut) (err error) {
	if uid := tryVerifTok(in.Token); uid != -1 {
		if err := db.VerifyUser(uid); err != nil {
			return fmt.Errorf("Can't verify user '%d': %s", uid, err)
		}

		// XXX Alright, this is convenient, but maybe we'd want
		// to think more about it; pretty sure I'd prefer to have
		// a genuine JWT token in in.Token.
		out.Token, err = NewToken(uid)
		return err
	}
	return fmt.Errorf("Invalid token")
}

// For quick tests: curl -X POST -d '{"Name": "user" }' localhost:7070/signin
// XXX: Why is the loaded conf shared (module-wise) but not the DB?
func New(db DB) *http.ServeMux {
	mux := http.NewServeMux()

	// We could automatically detect types via reflection. Or generate
	// this with a shell script or whatnot.

	// signin from an email/username/password
	mux.HandleFunc("/signin", wrap[SigninIn, SigninOut](db, Signin))

	mux.HandleFunc("/signout", wrap[SignoutIn, SignoutOut](db, Signout))

	mux.HandleFunc("/login", wrap[LoginIn, LoginOut](db, Login))

	// Check a token's validity/update it
	mux.HandleFunc("/chain", wrap[ChainIn, ChainOut](db, Chain))

	// Check a token's validity
	mux.HandleFunc("/check", wrap[CheckIn, CheckOut](db, Check))

	mux.HandleFunc("/logout", wrap[LogoutIn, LogoutOut](db, Logout))

	// email ownership verification upon signin,
	// followed by an automatic login.
	mux.HandleFunc("/verify", wrap[VerifyIn, VerifyOut](db, Verify))

	// Password/email edition
	mux.HandleFunc("/edit", wrap[EditIn, EditOut](db, Edit))

	return mux
}
