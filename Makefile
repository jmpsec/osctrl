export GO111MODULE=on

SHELL := /bin/bash

TLS_DIR = tls
TLS_NAME = osctrl-tls
TLS_CODE = ${TLS_DIR:=/*.go}

ADMIN_DIR = admin
ADMIN_NAME = osctrl-admin
ADMIN_CODE = ${ADMIN_DIR:=/*.go}

API_DIR = api
API_NAME = osctrl-api
API_CODE = ${API_DIR:=/*.go}

CLI_DIR = cli
CLI_NAME = osctrl-cli
CLI_CODE = ${CLI_DIR:=/*.go}

DEST ?= /opt/osctrl

OUTPUT = bin

STATIC_ARGS = -ldflags "-linkmode external -extldflags -static"

.PHONY: build static clean tls admin cli api

# Build code according to caller OS and architecture
build:
	make tls
	make admin
	make api
	make cli

# Build everything statically
static:
	make tls-static
	make admin-static
	make api-static
	make cli-static

# Build TLS endpoint
tls:
	go build -o $(OUTPUT)/$(TLS_NAME) $(TLS_CODE)

# Build TLS endpoint statically
tls-static:
	go build $(STATIC_ARGS) -o $(OUTPUT)/$(TLS_NAME) -a $(TLS_CODE)

# Build Admin UI
admin:
	go build -o $(OUTPUT)/$(ADMIN_NAME) $(ADMIN_CODE)

# Build Admin UI statically
admin-static:
	go build $(STATIC_ARGS) -o $(OUTPUT)/$(ADMIN_NAME) -a $(ADMIN_CODE)

# Build API
api:
	go build -o $(OUTPUT)/$(API_NAME) $(API_CODE)

# Build API statically
api-static:
	go build $(STATIC_ARGS) -o $(OUTPUT)/$(API_NAME) -a $(API_CODE)

# Build the CLI
cli:
	go build -o $(OUTPUT)/$(CLI_NAME) $(CLI_CODE)

# Build the CLI statically
cli-static:
	go build $(STATIC_ARGS) -o $(OUTPUT)/$(CLI_NAME) -a $(CLI_CODE)

# Delete all compiled binaries
clean:
	rm -rf $(OUTPUT)/$(TLS_NAME)
	rm -rf $(OUTPUT)/$(ADMIN_NAME)
	rm -rf $(OUTPUT)/$(API_NAME)
	rm -rf $(OUTPUT)/$(CLI_NAME)

# Dekete all dependencies go.sum files
clean_go:
	find . -name "go.sum" -type f -exec rm -rf {} \;

# Remove all unused dependencies
tidy:
	make clean
	make clean_go
	go mod tidy

# Install everything
# optional DEST=destination_path
install:
	make clean
	make build
	make install_tls
	make install_admin
	make install_api
	make install_cli

# Install TLS server and restart service
# optional DEST=destination_path
install_tls:
	sudo systemctl stop $(TLS_NAME)
	sudo cp $(OUTPUT)/$(TLS_NAME) $(DEST)
	sudo systemctl start $(TLS_NAME)

# Install Admin server and restart service
# optional DEST=destination_path
install_admin:
	sudo systemctl stop $(ADMIN_NAME)
	sudo cp $(OUTPUT)/$(ADMIN_NAME) $(DEST)
	sudo systemctl start $(ADMIN_NAME)

# Install API server and restart service
# optional DEST=destination_path
install_api:
	sudo systemctl stop $(API_NAME)
	sudo cp $(OUTPUT)/$(API_NAME) $(DEST)
	sudo systemctl start $(API_NAME)

# Install CLI
# optional DEST=destination_path
install_cli:
	sudo cp $(OUTPUT)/$(CLI_NAME) $(DEST)

# Display systemd logs for TLS server
logs_tls:
	sudo journalctl -f -t $(TLS_NAME)

# Display systemd logs for Admin server
logs_admin:
	sudo journalctl -f -t $(ADMIN_NAME)

# Display systemd logs for API server
logs_api:
	sudo journalctl -f -t $(API_NAME)

# Destroy existing vagrant development VM
vagrant_destroy:
	rm -Rf certs/*
	vagrant destroy -f

# Bring up a vagrant VM for local development
vagrant_up:
	make vagrant_destroy
	mkdir -p "certs"
	mkcert -key-file "certs/osctrl-admin.key" -cert-file "certs/osctrl-admin.crt" "osctrl.dev"
	vagrant up

# Build docker containers and run them (also generates new certificates)
docker_all:
	./deploy/docker/dockerize.sh -u -b -f

# Run docker containers
docker_up:
	./deploy/docker/dockerize.sh -u

# Build docker containers
docker_build:
	./deploy/docker/dockerize.sh -b

# Takes down docker containers
docker_down:
	./deploy/docker/dockerize.sh -d

# Cleans docker containers and certificates
docker_clean:
	make docker_down
	./deploy/docker/dockerize.sh -x
	rm -Rf deploy/docker/certs/*
	rm -Rf deploy/docker/config/*
	docker volume rm osctrl_db-data

# Auto-format and simplify the code
GOFMT_ARGS = -l -w -s
gofmt-tls:
	gofmt $(GOFMT_ARGS) ./$(TLS_CODE)

gofmt-admin:
	gofmt $(GOFMT_ARGS) ./$(ADMIN_CODE)

gofmt-api:
	gofmt $(GOFMT_ARGS) ./$(API_CODE)

gofmt-cli:
	gofmt $(GOFMT_ARGS) ./$(CLI_CODE)

# Run all tests
test:
	go clean -testcache ./...
	go test ./utils -v
	go test ./tls/handlers -v

# Check test coverage
test_cover:
	cd utils && go test -cover .
	cd tls/handlers && go test -cover .
