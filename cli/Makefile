.PHONY: all build clean tidy

BINARY_NAME=secureshare-cli

all: tidy build

tidy:
	go mod tidy

build:
	go build -o $(BINARY_NAME) main.go

build-all: tidy
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_NAME).exe main.go
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)-linux main.go
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_NAME)-mac main.go

clean:
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME).exe
	rm -f $(BINARY_NAME)-linux
	rm -f $(BINARY_NAME)-mac
