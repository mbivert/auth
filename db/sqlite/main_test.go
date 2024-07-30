package sqlite

// NOTE: there's little reasons for this test file not to
// work for any other databases (e.g. PostgreSQL) in the future,
// besides a few minor tweaks.

import (
	"testing"
	"time"
	"os"
	"fmt"
	"log"
	auth "github.com/mbivert/auth/user"
	"github.com/mbivert/ftests"
)

var db *DB

// Individual tests rely on a ~fresh DB; "init()" cannot be
// called directly.
func init2() {
	dbfn := "./db_test.sqlite"
	err := os.RemoveAll(dbfn) // won't complain if dbfn doesn't exist
	if err != nil {
		log.Fatal(err)
	}
	db, err = New(dbfn)
	if err != nil {
		log.Fatal(err)
	}

}

func TestAddUser(t *testing.T) {
	init2()

	now := time.Now().Unix()

	ftests.Run(t, []ftests.Test{
		{
			"'bad' user allowed: checks are externals",
			db.AddUser,
			[]interface{}{&auth.User{
				Id       : 0,
				Name     : "t",
				Email    : "t",
				Passwd   : "t",
				Verified : false,
				CDate    : now,
			}},
			[]interface{}{nil},
		},
		{
			"Can't have the same username twice",
			db.AddUser,
			[]interface{}{&auth.User{
				Id       : 0,
				Name     : "t",
				Email    : "t0",
				Passwd   : "t",
				Verified : false,
				CDate    : now,
			}},
			[]interface{}{fmt.Errorf("Username already used")},
		},
		{
			"Can't have the same email twice",
			db.AddUser,
			[]interface{}{&auth.User{
				Id       : 0,
				Name     : "t0",
				Email    : "t",
				Passwd   : "t",
				Verified : false,
				CDate    : now,
			}},
			[]interface{}{fmt.Errorf("Email already used")},
		},
	})
}

func getUser(login string) (*auth.User, error) {
	var u auth.User
	u.Name  = login
	u.Email = login
	if err := db.GetUser(&u); err != nil {
		return nil, err
	}
	return &u, nil
}

func TestVerifyUser(t *testing.T) {
	init2()

	now := time.Now().Unix()

	name  := "t"

	ftests.Run(t, []ftests.Test{
		{
			"Registering a random user",
			db.AddUser,
			[]interface{}{&auth.User{
				Id       : 0,
				Name     : name,
				Email    : "t0",
				Passwd   : "t",
				Verified : false,
				CDate    : now,
			}},
			[]interface{}{nil},
		},
		{
			"Verifying an existing user (using name)",
			db.VerifyUser,
			[]interface{}{name},
			[]interface{}{nil},
		},
		{
			"User has indeed been verified",
			getUser,
			[]interface{}{name},
			[]interface{}{&auth.User{
				Id       : 0,
				Name     : name,
				Email    : "t0",
				Passwd   : "t",
				Verified : true,
				CDate    : now,
			}, nil},
		},
		{
			"Verifying an in-existing user",
			db.VerifyUser,
			[]interface{}{"nope"},
			[]interface{}{fmt.Errorf(
				"Invalid username",
			)},
		},
	})
}

func TestGetUser(t *testing.T) {
	init2()

	now := time.Now().Unix()

	// nil user pointer
	var u *auth.User

	name  := "t"
	email := "t0"

	// NOTE: we're testing the verified=true
	// case in TestVerifyUser()
	ftests.Run(t, []ftests.Test{
		{
			"Registering a random user",
			db.AddUser,
			[]interface{}{&auth.User{
				Id       : 0,
				Name     : name,
				Email    : email,
				Passwd   : "t",
				Verified : false,
				CDate    : now,
			}},
			[]interface{}{nil},
		},
		{
			"Retrieving user by name",
			getUser,
			[]interface{}{name},
			[]interface{}{&auth.User{
				Id       : 0,
				Name     : name,
				Email    : email,
				Passwd   : "t",
				Verified : false,
				CDate    : now,
			}, nil},
		},
		{
			"Retrieving user by email",
			getUser,
			[]interface{}{email},
			[]interface{}{&auth.User{
				Id       : 0,
				Name     : name,
				Email    : email,
				Passwd   : "t",
				Verified : false,
				CDate    : now,
			}, nil},
		},
		{
			"Retrieving inexisting user",
			getUser,
			[]interface{}{"nope"},
			[]interface{}{u, fmt.Errorf(
				"Invalid username or email",
			)},
		},
	})
}

func TestRmUser(t *testing.T) {
	init2()

	now := time.Now().Unix()

	// nil user pointer
	var u *auth.User

	name  := "t"

	ftests.Run(t, []ftests.Test{
		{
			"Registering a random user",
			db.AddUser,
			[]interface{}{&auth.User{
				Id       : 0,
				Name     : name,
				Email    : "t",
				Passwd   : "t",
				Verified : false,
				CDate    : now,
			}},
			[]interface{}{nil},
		},
		{
			"Deleting our user",
			db.RmUser,
			[]interface{}{name},
			[]interface{}{"t", nil},
		},
		{
			"User has indeed been deleted",
			getUser,
			[]interface{}{name},
			[]interface{}{u, fmt.Errorf(
				"Invalid username or email",
			)},
		},
		{
			"Can't delete an inexisting user",
			db.RmUser,
			[]interface{}{name},
			[]interface{}{"", fmt.Errorf(
				"Invalid username",
			)},
		},
	})
}
