package main

import (
	auth "github.com/mbivert/auth"
	"github.com/mbivert/auth/db/sqlite"
	"net/http"
	"log"
)

func main() {
	// TODO: cli parameter
	port := ":7070"

	// XXX meh, this gets created in ../db.sqlite when launched
	// by Run -m dev-site
	fn   := "db.sqlite"

	db, err := sqlite.New(fn)
	if err != nil {
		log.Fatal(err)
	}

	// Mind the slashes
	http.Handle("/auth/", http.StripPrefix("/auth", auth.New(db)))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index_test.html")
	})

	log.Println("Listening on "+port)
	log.Fatal(http.ListenAndServe(port, nil))


/*
	mux := http.NewServeMux()
//	mux.Handle("/auth/signin/", auth.New(db))
	mux.Handle("/auth/", http.StripPrefix("/auth", auth.New(db)))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		println("/ handler; "+r.URL.Path)
		// The "/" pattern matches everything, so we need to check
		// that we're at the root here.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "index_test.html")
	})

	log.Println("Listening on "+port)
	log.Fatal(http.ListenAndServe(port, mux))
*/
}
