package sqlite

// implements auth.DB (../../types.go:/type DB interface);
// indirectly tested via ../../auth_test.go

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	auth "github.com/mbivert/auth/user"
	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	*sql.DB
	*sync.Mutex
}

func New(fn string) (*DB, error) {
	db, err := sql.Open("sqlite3", "file:"+fn)

	if err != nil {
		return nil, err
	}

	sdb := &DB{db,&sync.Mutex{}}

	return sdb, sdb.AddTable()
}

func (db *DB) AddTable() error {
	db.Lock()
	defer db.Unlock()

	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS
		users(
			id                      INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
			name        TEXT        UNIQUE,
			email       TEXT        UNIQUE,
			passwd      TEXT,
			verified    INTEGER,
			cdate       INTEGER
		)
	`)
	return err
}

// XXX/TODO: we're likely leaking email address bytes
// https://www.usenix.org/system/files/sec21-shahverdi.pdf also
// https://faculty.cc.gatech.edu/~orso/papers/halfond.viegas.orso.ISSSE06.pdf
func (db *DB) AddUser(u *auth.User) error {
	db.Lock()
	defer db.Unlock()

	// TODO: clarify exec vs. query (is there a prepare here?)
	err := db.QueryRow(`INSERT INTO
		users(name, email, passwd, verified, cdate)
		VALUES($1, $2, $3, $4, $5)
		RETURNING id`, u.Name, u.Email, u.Passwd, u.Verified, u.CDate,
	).Scan(&u.Id)

	// Improve error message (this is for tests purposes: caller
	// is expected to provide end user with something less informative)
	if err != nil && err.Error() == "UNIQUE constraint failed: users.email" {
		err = fmt.Errorf("Email already used")
	}
	if err != nil && err.Error() == "UNIQUE constraint failed: users.name" {
		err = fmt.Errorf("Username already used")
	}

	return err
}

func (db *DB) EnableUser(u *auth.User) error {
	db.Lock()
	defer db.Unlock()

	// TODO: clarify exec vs. query (is there a prepare here?)
//	err := db.QueryRow(`
	_, err := db.Exec(`
		UPDATE
			users
		SET
			verified = $1
		WHERE
			name  = $1
		AND email = $2
	`, true, u.Name, u.Email)

	// Improve error message
	if errors.Is(err, sql.ErrNoRows) {
		err = fmt.Errorf("Invalid login or password")
	}

	u.Verified = true

	return err
}

func (db *DB) GetUser(u *auth.User) error {
	db.Lock()
	defer db.Unlock()

	// TODO: clarify exec vs. query (is there a prepare here?)
	err := db.QueryRow(`SELECT
			name, email, passwd
		FROM users WHERE
			name  = $1
		OR  email = $2
	`, u.Name, u.Email).Scan(&u.Name, &u.Email, &u.Passwd)

	// Improve error message
	if errors.Is(err, sql.ErrNoRows) {
		err = fmt.Errorf("Invalid login or password")
	}

	return err
}

func (db *DB) RmUser(name string) (email string, err error) {
	db.Lock()
	defer db.Unlock()

	err = db.QueryRow(`DELETE FROM users WHERE name = $1
		RETURNING email`, name).Scan(&email)

	return email, err
}

func (db *DB) EditUser() error {
	return fmt.Errorf("TODO")
}
