.PHONY: all build clean tidy

BINARY_NAME=secureshare-cli

all: tidy build

tidy:
	go mod tidy

build:
	go build -o $(BINARY_NAME) .

build-all: tidy
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_NAME).exe .
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)-linux .
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_NAME)-mac-arm64 .
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_NAME)-mac-intel .

clean:
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME).exe
	rm -f $(BINARY_NAME)-linux
	rm -f $(BINARY_NAME)-mac-arm64
	rm -f $(BINARY_NAME)-mac-intel
