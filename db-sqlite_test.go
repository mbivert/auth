package auth

// NOTE: there's little reasons for this test file not to
// work for any other databases (e.g. PostgreSQL) in the future,
// besides a few minor tweaks.

import (
	"testing"
	"time"
	"os"
	"fmt"
	"log"
	"github.com/mbivert/ftests"
)

var db *SQLiteDB

// Individual tests rely on a ~fresh DB; "init()" cannot be
// called directly.
func initsqlitetest() {
	dbfn := "./db_test.sqlite"
	err := os.RemoveAll(dbfn) // won't complain if dbfn doesn't exist
	if err != nil {
		log.Fatal(err)
	}
	db, err = NewSQLite(dbfn)
	if err != nil {
		log.Fatal(err)
	}
}

func getUser(login string) (*User, error) {
	var u User
	u.Name  = login
	u.Email = login
	if err := db.GetUser(&u); err != nil {
		return nil, err
	}
	return &u, nil
}

func TestAddUser(t *testing.T) {
	initsqlitetest()

	now := time.Now().Unix()

	ftests.Run(t, []ftests.Test{
		{
			"'bad' user allowed: checks are externals",
			db.AddUser,
			[]any{&User{
				Id       : 0,
				Name     : "t",
				Email    : "t",
				Passwd   : "t",
				Verified : false,
				CDate    : now,
			}},
			[]any{nil},
		},
		{
			"Can't have the same username twice",
			db.AddUser,
			[]any{&User{
				Id       : 0,
				Name     : "t",
				Email    : "t0",
				Passwd   : "t",
				Verified : false,
				CDate    : now,
			}},
			[]any{fmt.Errorf("Username already used")},
		},
		{
			"Can't have the same email twice",
			db.AddUser,
			[]any{&User{
				Id       : 0,
				Name     : "t0",
				Email    : "t",
				Passwd   : "t",
				Verified : false,
				CDate    : now,
			}},
			[]any{fmt.Errorf("Email already used")},
		},
	})
}

func TestVerifyUser(t *testing.T) {
	initsqlitetest()

	now := time.Now().Unix()

	u := User{
		Id       : 0,
		Name     : "t",
		Email    : "t0",
		Passwd   : "t",
		Verified : false,
		CDate    : now,
	}

	ftests.Run(t, []ftests.Test{
		{
			"Registering a random user",
			db.AddUser,
			[]any{&u},
			[]any{nil},
		},
		{
			"Make sure our ID is correct",
			func(u *User, uid UserId) bool { return u.Id == uid },
			[]any{&u, UserId(1)},
			[]any{true},
		},
		// NOTE: we can't use u.ID below, because it'll be
		// computed at compile time, while we wants its
		// value after we have executed the AddUser. Hence
		// the previous test/assertion
		{
			"Verifying an existing user",
			db.VerifyUser,
			[]any{UserId(1)},
			[]any{nil},
		},
		{
			"User has indeed been verified",
			getUser,
			[]any{u.Name},
			[]any{&User{
				Id       : 1,
				Name     : "t",
				Email    : "t0",
				Passwd   : "t",
				Verified : true,
				CDate    : now,
			}, nil},
		},
		{
			"Verifying an in-existing user",
			db.VerifyUser,
			[]any{UserId(42)},
			[]any{fmt.Errorf(
				"Invalid uid",
			)},
		},
	})
}

func TestGetUser(t *testing.T) {
	initsqlitetest()

	now := time.Now().Unix()

	// nil user pointer
	var x *User

	name  := "t"
	email := "t0"

	u := User{
		Id       : 0,
		Name     : name,
		Email    : email,
		Passwd   : "t",
		Verified : false,
		CDate    : now,
	}

	// NOTE: we're testing the verified=true
	// case in TestVerifyUser()
	ftests.Run(t, []ftests.Test{
		{
			"Registering a random user",
			db.AddUser,
			[]any{&u},
			[]any{nil},
		},
		{
			"Make sure our ID is correct",
			func(u *User, uid UserId) bool { return u.Id == uid },
			[]any{&u, UserId(1)},
			[]any{true},
		},
		// NOTE: we can't use u.ID below, because it'll be
		// computed at compile time, while we wants its
		// value after we have executed the AddUser. Hence
		// the previous test/assertion
		{
			"Retrieving user by name",
			getUser,
			[]any{name},
			[]any{&u, nil},
		},
		{
			"Retrieving user by email",
			getUser,
			[]any{email},
			[]any{&u, nil},
		},
		{
			"Retrieving inexisting user",
			getUser,
			[]any{"nope"},
			[]any{x, fmt.Errorf(
				"Invalid username or email",
			)},
		},
	})
}

func TestRmUser(t *testing.T) {
	initsqlitetest()

	now := time.Now().Unix()

	// nil user pointer
	var x *User

	name  := "t"

	u := User{
		Id       : 0,
		Name     : name,
		Email    : "t",
		Passwd   : "t",
		Verified : false,
		CDate    : now,
	}

	ftests.Run(t, []ftests.Test{
		{
			"Registering a random user",
			db.AddUser,
			[]any{&u},
			[]any{nil},
		},
		{
			"Make sure our ID is correct",
			func(u *User, uid UserId) bool { return u.Id == uid },
			[]any{&u, UserId(1)},
			[]any{true},
		},
		// NOTE: we can't use u.ID below, because it'll be
		// computed at compile time, while we wants its
		// value after we have executed the AddUser. Hence
		// the previous test/assertion
		{
			"Deleting our user",
			db.RmUser,
			[]any{UserId(1)},
			[]any{"t", nil},
		},
		{
			"User has indeed been deleted",
			getUser,
			[]any{name},
			[]any{x, fmt.Errorf(
				"Invalid username or email",
			)},
		},
		{
			"Can't delete an inexisting user",
			db.RmUser,
			[]any{UserId(42)},
			[]any{"", fmt.Errorf(
				"Invalid uid",
			)},
		},
	})
}
