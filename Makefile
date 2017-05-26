BUMP_VERSION := $(shell command -v bump_version)
MEGACHECK := $(shell command -v megaccheck)

IGNORES := 'github.com/kevinburke/ssh_config/config.go:U1000 github.com/kevinburke/ssh_config/config.go:S1002 github.com/kevinburke/ssh_config/token.go:U1000'

lint:
	go vet ./...
ifndef MEGACHECK
	go get -u honnef.co/go/tools/cmd/megacheck
endif
	megacheck --ignore=$(IGNORES) ./...

test: lint
	@# the timeout helps guard against infinite recursion
	go test -timeout=50ms ./...

release:
ifndef BUMP_VERSION
	go get -u github.com/Shyp/bump_version
endif
	bump_version minor config.go
