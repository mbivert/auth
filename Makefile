port = 7070

.PHONY: dev-site
dev-site:
	@echo "(Re)starting dev site on ${port}..."
	@lsof -i -P -n|awk '/TCP.*'${port}'.*LISTEN/ { print "kill " $$2 }' | sh
	@go run cmd/auth.go

.PHONY: tests
tests: private.pem public.pem
	@echo Running tests...
	@go test -v

.PHONY: tests-db-sqlite
tests-db-sqlite: db/sqlite/main.go db/sqlite/main_test.go
	@echo Running token tests...
	@go test -v $?

.PHONY: tests-token
tests-token: token_test.go token.go config.go ftests.go utils.go
	@echo Running token tests...
	@go test -v $?

private.pem public.pem: genkeys.sh
	@echo Generating '(dummy)' private/public keys...
	@sh genkeys.sh
