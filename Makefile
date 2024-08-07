port = 7070

.PHONY: dev-site
dev-site:
	@echo "(Re)starting dev site on ${port}..."
	@lsof -i -P -n|awk '/TCP.*'${port}'.*LISTEN/ { print "kill " $$2 }' | sh
	@go run cmd/auth.go

.PHONY: tests
tests: private.pem public.pem
	@echo Running tests...
	@go test -v .

.PHONY: db-sqlite-tests
db-sqlite-tests: db-sqlite_test.go db-sqlite.go types.go
	@echo Running SQLite DB tests...
	@go test -v $^

.PHONY: token-tests
token-tests: token_test.go token.go config.go utils.go types.go
	@echo Running token tests...
	@go test -v $^

.PHONY: auth-tests
auth-tests: auth_test.go auth.go token.go config.go utils.go types.go db-sqlite.go
	@echo Running auth tests...
	@go test -v $^

private.pem public.pem: genkeys.sh
	@echo Generating '(dummy)' private/public keys...
	@sh genkeys.sh
