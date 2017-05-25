BUMP_VERSION := $(shell command -v bump_version)
STATICCHECK := $(shell command -v staticcheck)

lint:
	go vet ./...
ifndef STATICCHECK
	go get -u honnef.co/go/tools/cmd/staticcheck
endif
	staticcheck ./...

test: lint
	@# the timeout helps guard against infinite recursion
	go test -timeout=50ms ./...

release:
ifndef BUMP_VERSION
	go get -u github.com/Shyp/bump_version
endif
	bump_version minor config.go
