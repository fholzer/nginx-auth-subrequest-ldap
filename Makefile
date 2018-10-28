GO_FILES=$(shell find . -type f -name '*.go')

nginx-auth-subrequest-ldap: $(GO_FILES)
	go build -ldflags "-s -w"

setup:
	go get github.com/fzipp/gocyclo
	go get -u golang.org/x/lint/golint
	go get github.com/gordonklaus/ineffassign
	go get -u github.com/client9/misspell/cmd/misspell
	dep ensure

prepare:
	go fmt -x .
	go vet .
	gocyclo -over 15 main.go
	golint
	ineffassign .
	misspell -error main
