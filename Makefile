.PHONY: test test-cover build release-builds

VERSION := `git fetch --tags && git tag | sort -V | tail -1`
PKG=github.com/zricethezav/gitleaks-ng
LDFLAGS=-ldflags "-X=github.com/zricethezav/gitleaks-ng/version.Version=$(VERSION)"
COVER=--cover --coverprofile=cover.out

test-cover:
	go test ./... --race $(COVER) $(PKG) -v
	go tool cover -html=cover.out

test:
	go get golang.org/x/lint/golint
	go fmt
	golint
	go test ./... --race $(PKG) -v

test-integration:
	go test github.com/zricethezav/gitleaks-ng/hosts -v -integration

build:
	go mod tidy
	go build $(LDFLAGS)

release-builds:
	rm -rf build
	mkdir build
	env GOOS="windows" GOARCH="amd64" go build -o "build/gitleaks-windows-amd64.exe"
	env GOOS="windows" GOARCH="386" go build -o "build/gitleaks-windows-386.exe"
	env GOOS="linux" GOARCH="amd64" go build -o "build/gitleaks-linux-amd64"
	env GOOS="linux" GOARCH="arm" go build -o "build/gitleaks-linux-arm"
	env GOOS="linux" GOARCH="mips" go build -o "build/gitleaks-linux-mips"
	env GOOS="linux" GOARCH="mips" go build -o "build/gitleaks-linux-mips"
	env GOOS="darwin" GOARCH="amd64" go build -o "build/gitleaks-darwin-amd64"


