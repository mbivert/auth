package main

import (
	"github.com/mbivert/auth"
	"github.com/mbivert/auth/db/sqlite"
	"log"
	"net/http"
)

func main() {
	// TODO: cli parameter
	port := ":7070"
	fn   := "db.sqlite"

	db, err := sqlite.New(fn)

	if err != nil {
		log.Fatal(err)
	}

	log.Println("Listening on ", port)
    log.Fatal(http.ListenAndServe(port, auth.New(db)))
}
