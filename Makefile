SHELL := /bin/bash

TLS_DIR = src/tls
TLS_NAME = osctrl-tls
TLS_CODE = ${TLS_DIR:=/*.go}

CLI_DIR = src/cli
CLI_NAME = osctrl-cli
CLI_CODE = ${CLI_DIR:=/*.go}

DEST ?= /opt/osctrl
 
# Build code according to caller OS and architecture
build:
	make tls
	make cli

# Build TLS endpoint
tls:
	GOPATH=${CURDIR} go build -o $(TLS_NAME) $(TLS_CODE)

# Build the CLI
cli:
	GOPATH=${CURDIR} go build -o $(CLI_NAME) $(CLI_CODE)

# Install the dependencies for TLS and CLI
deps:
	cd $(TLS_DIR) && GOPATH=${CURDIR} glide install
	cd $(CLI_DIR) && GOPATH=${CURDIR} glide install

# Update glide.lock file to include latest versions of all dependences
# Must be run whenever glide.yaml changes
update-deps:
	cd $(TLS_DIR) && GOPATH=${CURDIR} glide update
	cd $(CLI_DIR) && GOPATH=${CURDIR} glide update
 
# Delete all compiled binaries
clean:
	rm -rf $(TLS_NAME)
	rm -rf $(CLI_NAME)

# Delete dependencies, run "make install" to bring them back
clean-deps:
	rm -Rf $(TLS_DIR)/vendor
	rm -Rf $(CLI_DIR)/vendor

# Install everything
# optional DEST=destination_path
install:
	make clean
	make build
	make install_tls
	make install_cli

# Install TLS server and restart service
# optional DEST=destination_path
install_tls:
	sudo systemctl stop $(TLS_NAME)
	sudo cp $(TLS_NAME) $(DEST)
	sudo systemctl start $(TLS_NAME)

# Install CLI
# optional DEST=destination_path
install_cli:
	sudo cp $(CLI_NAME) $(DEST)

# Auto-format and simplify the code
GOFMT_ARGS = -l -w -s
gofmt-tls:
	GOPATH=${CURDIR} gofmt $(GOFMT_ARGS) ./$(TLS_CODE)

gofmt-cli:
	GOPATH=${CURDIR} gofmt $(GOFMT_ARGS) ./$(CLI_CODE)

# Run all tests
test:
	# Install dependencies for TLS
	cd $(TLS_DIR) && GOPATH=${CURDIR} go test -i . -v
	# Run TLS tests
	cd $(TLS_DIR) && GOPATH=${CURDIR} go test . -v
	# Install dependencies for CLI
	cd $(CLI_DIR) && GOPATH=${CURDIR} go test -i . -v
	# Run CLI tests
	cd $(CLI_DIR) && GOPATH=${CURDIR} go test . -v