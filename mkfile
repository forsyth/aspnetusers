all:V:
	go build .

fmt:V:
	go fmt .

test:V:
	. ./testdata/secrets.rc
	export USERS_DSN
	go test -v .

testcov:V:
	go test -v -coverprofile'='c.out .

vet:V:
	go vet .

view:V:
	go tool cover -html'='c.out
