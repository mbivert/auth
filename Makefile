port = 7070

.PHONY: dev-site
dev-site:
	@echo "(Re)starting dev site on ${port}..."
	@lsof -i -P -n|awk '/TCP.*'${port}'.*LISTEN/ { print "kill " $$2 }' | sh
	@go run cmd/auth.go

.PHONY: tests
tests:
	@echo Running tests...
	@go test -v
