all:V:
	go build .

fmt:V:
	go fmt .

test:V:
	go test -v .

vet:V:
	go vet .
