
## small @split-auth-user-management
	We may want to keep that module as small as possible, and
	delegate user management to another module.

	This means keeping login/logout/token chaining only here.

	db-sqlite.go would shrink, as we would only require a db.GetUser():
	it's unlikely that in any practical application the caller would
	want to use our db-sqlite.go anyway, as e.g. they'd want different
	field names, or additional data. Which mean they would have to
	implement their own auth.DB.

## small @clarify-token-chaining
	From what I understand (!) of what I've read (!), per request
	chaining is marginally more secure than having a per-session
	token, and the well-known usablity drawback, at least given
	how things are currently designed (one token per user), is that
	we can't have two tabs opened with the same connected user.

	The chaining could still be useful for long sessions.

## small/medium @token-as-http-cookie
	Seems like it's a better default than having the cookie
	directly available to JS.

## small/medium @json-rpc
	Perhaps it'd be wise to either implement the service via JSON-RPC
	(but still provide a HTTP frontend). FWIW, there are *2* recent
	implementations in x/tools/internal:
		- https://pkg.go.dev/golang.org/x/tools/internal/jsonrpc2
		- https://pkg.go.dev/golang.org/x/tools@v0.24.0/internal/jsonrpc2_v2
