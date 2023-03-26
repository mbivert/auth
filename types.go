package auth

import (
	auth "github.com/mbivert/auth/user"
)

// implemented by sqlite/main.go; used at least for tests
type DB interface {
	AddUser(*auth.User) error
	GetUser(*auth.User) error
	RmUser(string) (string, error)
	EditUser() error
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

type SigninOut struct {}

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

type LogoutOut struct {}

type SignoutIn struct {
	Token  string `json:"token"`
}

type SignoutOut struct {}

type ChainIn struct {
	Token  string `json:"token"`
}

type ChainOut struct {
	Token  string `json:"token"`
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
