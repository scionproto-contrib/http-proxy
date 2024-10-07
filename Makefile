# Variables
BINARY_NAMES=scion-caddy scion-caddy-forward scion-caddy-reverse
SRC_DIR=./cmd
BUILD_DIR=./build

# Go commands
GO=go
GOFMT=gofmt
GOTEST=$(GO) test
GOBUILD=$(GO) build
GOCLEAN=$(GO) clean
GOVET=$(GO) vet

# Build the project
all: test build

# Format the code
fmt:
	$(GOFMT) -w .

lint:
	@type golangci-lint > /dev/null || ( echo "golangci-lint not found. Install it manually"; exit 1 )
	golangci-lint run --timeout=2m

# Run tests
test:
	$(GOTEST) ./...

# Build all binaries
build: $(BINARY_NAMES)

# Build each binary
$(BINARY_NAMES):
	$(GOBUILD) -o $(BUILD_DIR)/$@ $(SRC_DIR)/$@

# Build for Windows
build-windows:
	GOOS=windows GOARCH=amd64 $(MAKE) build

# Build for macOS
build-macos:
	GOOS=darwin GOARCH=amd64 $(MAKE) build

# Build for Linux
build-linux:
	GOOS=linux GOARCH=amd64 $(MAKE) build

# Clean the build directory
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

# Run go vet
vet:
	$(GOVET) ./...

.PHONY: all fmt lint test build clean vet $(BINARY_NAMES) build-windows build-macos build-linux
