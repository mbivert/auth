package auth

/*
 * Implements auth.DB (../../types.go:/type DB interface).
 */

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	_ "github.com/mattn/go-sqlite3"
)

type SQLiteDB struct {
	*sql.DB
	*sync.Mutex
}

func NewSQLite(path string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite3", "file:"+path)

	if err != nil {
		return nil, err
	}

	sdb := &SQLiteDB{db,&sync.Mutex{}}

	return sdb, sdb.AddTable()
}

func (db *SQLiteDB) AddTable() error {
	db.Lock()
	defer db.Unlock()

	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS
		User (
			Id                      INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
			Name        TEXT        UNIQUE,
			Email       TEXT        UNIQUE,
			Passwd      TEXT,
			Verified    INTEGER,
			CDate       INTEGER
		)
	`)
	return err
}

// XXX/TODO: we're probably leaking email address bytes
// https://www.usenix.org/system/files/sec21-shahverdi.pdf also
// https://faculty.cc.gatech.edu/~orso/papers/halfond.viegas.orso.ISSSE06.pdf
func (db *SQLiteDB) AddUser(u *User) error {
	db.Lock()
	defer db.Unlock()

	// TODO: clarify exec vs. query (is there a prepare here?)
	err := db.QueryRow(`INSERT INTO
		User (Name, Email, Passwd, Verified, CDate)
		VALUES($1, $2, $3, $4, $5)
		RETURNING Id`, u.Name, u.Email, u.Passwd, u.Verified, u.CDate,
	).Scan(&u.Id)

	// Improve error message (this is for tests purposes: caller
	// is expected to provide end user with something less informative)
	if err != nil && err.Error() == "UNIQUE constraint failed: User.Email" {
		err = fmt.Errorf("Email already used")
	}
	if err != nil && err.Error() == "UNIQUE constraint failed: User.Name" {
		err = fmt.Errorf("Username already used")
	}

	return err
}


// XXX should be a (bool, error)
func (db *SQLiteDB) VerifyUser(uid UserId) error {
	db.Lock()
	defer db.Unlock()

	x := 0

	// NOTE: if we were only doing an .Exec, we wouldn't
	// be able to detect failure; returning a dumb row
	// on success allows us to check whether the update
	// did occured.
	err := db.QueryRow(`
		UPDATE
			User
		SET
			Verified = $1
		WHERE
			Id  = $2
		RETURNING
			1
	`, 1, uid).Scan(&x)


	if errors.Is(err, sql.ErrNoRows) {
		err = fmt.Errorf("Invalid uid")
	}

	return err
}

// XXX/TODO: any reasons for not (also) returning u?
func (db *SQLiteDB) GetUser(u *User) error {
	db.Lock()
	defer db.Unlock()

	verified := 0

	// TODO: clarify exec vs. query (is there a prepare here?)
	err := db.QueryRow(`SELECT
			Id, Name, Email, Passwd, Verified, CDate
		FROM User WHERE
			Name  = $1
		OR  Email = $2
	`, u.Name, u.Email).Scan(&u.Id, &u.Name, &u.Email, &u.Passwd, &verified, &u.CDate)

	if err == nil && verified > 0 {
		u.Verified = true
	}

	// Improve error message
	if errors.Is(err, sql.ErrNoRows) {
		err = fmt.Errorf("Invalid username or email")
	}

	return err
}

func (db *SQLiteDB) RmUser(uid UserId) (email string, err error) {
	db.Lock()
	defer db.Unlock()

	err = db.QueryRow(`DELETE FROM User WHERE Id = $1
		RETURNING Email`, uid).Scan(&email)

	if errors.Is(err, sql.ErrNoRows) {
		err = fmt.Errorf("Invalid uid")
	}

	return email, err
}

func (db *SQLiteDB) EditUser() error {
	return fmt.Errorf("TODO")
}
