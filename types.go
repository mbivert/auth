package auth

// The UserId is assumed to be immutable for any user
// (not like e.g. a username or an email)
type UserId int64

// implemented by sqlite/main.go; used at least for tests
type DB interface {
	AddUser(*User) error
	VerifyUser(UserId) error // verified email ownership
	GetUser(*User) error
	RmUser(UserId) (string, error)
	EditUser() error
}

type User struct {
	Id       UserId
	Name     string
	Email    string
	Passwd   string
	Verified bool
	CDate    int64
}

// this is just so we can have a specific JSON
// unmarshaller
type Email struct {
	string
}

// Endpoints input/output types
type SigninIn struct {
	Name   string `json:"name"`
	Passwd string `json:"passwd"`
	Email  Email  `json:"email"`
}

type SigninOut struct {
	Token  string `json:"token"`
}

type LoginIn struct {
	// Login is either a User.Name or a User.Email
	Login  string `json:"login"`
	Passwd string `json:"passwd"`
}

type LoginOut struct {
	Token  string `json:"token"`
}

type LogoutIn struct {
	Token  string `json:"token"`
}

type LogoutOut struct {
	Token  string `json:"token"`
}

type SignoutIn struct {
	Token  string `json:"token"`
}

type SignoutOut struct {
	Token  string `json:"token"`
}

type ChainIn struct {
	Token  string `json:"token"`
}

type ChainOut struct {
	Token  string `json:"token"`
}

type CheckIn struct {
	Token  string `json:"token"`
}

type CheckOut struct {
	Match  bool `json:"match"`
}

// NOTE/XXX: This is a "special" token, not the usual JWT
// token. Perhaps we could still use a JWT token here too.
type VerifyIn struct {
	Token string `json:"token"`
}

// Now this is a genuine token: upon success, we're also
// logging-in the user.
type VerifyOut struct {
	Token string `json:"token"`
}

// For edition to be successful:
//	- the password field *must* be correct;
//	- name, if present/updated, must be available;
//	- if newpasswd is empty, password isn't considered
//	to be changed;
//	- email, if present/updated, must be available,
//	and will trigger an email-verification sequence.
type EditIn struct {
	Token     string `json:"token"`
	Name      string `json:"name"`
	Passwd    string `json:"passwd"`
	NewPasswd string `json:"newpasswd"`
	Email     Email  `json:"email"`
}

type EditOut struct {
	Token string `json:"token"`
}
