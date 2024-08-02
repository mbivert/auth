
WIP (``go(1)`` RPC HTTPs authentication module)

# Overview
This package contains a RPC module to handle authentication related
tasks. We restrict ourself to a subset of HTTP to describe our
RPCs:

  - POST-only;
  - function name is represented by the static URL path;
  - *all* parameters are JSON-encoded (e.g. none are located
  in cookies, or in the URL path);
  - *all* returned values are JSON-encoded (e.g. nothing is sent
  as special headers, cookies);

This makes the implementation quite straightforward. If a route
format needs update, a new route can be added, e.g. ``/path/to/foo/v1.2``.
If the naming scheme is well-thought, it should be possible for clients
to predictibly try different versions of the same route, starting
with the most recent.

**<u>Note:</u>** This is a little unorthodox, especially for an
authentication module: for example, our tokens, instead of being
exchnaged via cookies, and sent encoded in a JSON blob,
``{ token : ... }``. But practically speaking, it's also way more
predictible: all inputs/outputs are always managed in the exact
same way everywhere.

Typically, you would reserve a prefix for those RPCs:

    import (
    	"github.com/mbivert/auth"
    	...
    )

    ...

    func main() {

    	...

    	db, err := auth.NewSQLite("db.sqlite")
    	if err != nil {
    		log.Fatal(err)
    	}

    	// Mind the slashes
    	http.Handle("/auth/", http.StripPrefix("/auth", auth.New(db)))

    	...

    }
