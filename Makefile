export GO111MODULE=on

SHELL := /bin/bash

TLS_DIR = cmd/tls
TLS_NAME = osctrl-tls
TLS_CODE = ${TLS_DIR:=/*.go}

ADMIN_DIR = cmd/admin
ADMIN_NAME = osctrl-admin
ADMIN_CODE = ${ADMIN_DIR:=/*.go}

API_DIR = cmd/api
API_NAME = osctrl-api
API_CODE = ${API_DIR:=/*.go}

CLI_DIR = cmd/cli
CLI_NAME = osctrl-cli
CLI_CODE = ${CLI_DIR:=/*.go}

PKGS_DIR = pkg
PLUGINS_DIR = plugins

DEST ?= /opt/osctrl

OUTPUT = bin

.PHONY: all build clean plugins

all: build

# Build code according to caller OS and architecture
build:
	make plugins
	make tls
	make admin
	make api
	make cli

# Build TLS endpoint
tls:
	go build -o $(OUTPUT)/$(TLS_NAME) $(TLS_CODE)

# Build Admin UI
admin:
	go build -o $(OUTPUT)/$(ADMIN_NAME) $(ADMIN_CODE)

# Build API
api:
	go build -o $(OUTPUT)/$(API_NAME) $(API_CODE)

# Build the CLI
cli:
	go build -o $(OUTPUT)/$(CLI_NAME) $(CLI_CODE)

# Build plugins
plugins:
	go build -buildmode=plugin -o $(PLUGINS_DIR)/logging_dispatcher_plugin.so $(PLUGINS_DIR)/logging_dispatcher/*.go
	go build -buildmode=plugin -o $(PLUGINS_DIR)/db_logging_plugin.so $(PLUGINS_DIR)/db_logging/*.go
	go build -buildmode=plugin -o $(PLUGINS_DIR)/graylog_logging_plugin.so $(PLUGINS_DIR)/graylog_logging/*.go
	go build -buildmode=plugin -o $(PLUGINS_DIR)/splunk_logging_plugin.so $(PLUGINS_DIR)/splunk_logging/*.go

# Delete all compiled binaries
clean:
	rm -rf $(OUTPUT)/$(TLS_NAME)
	rm -rf $(OUTPUT)/$(ADMIN_NAME)
	rm -rf $(OUTPUT)/$(API_NAME)
	rm -rf $(OUTPUT)/$(CLI_NAME)
	rm -rf $(PLUGINS_DIR)/*.so

# Remove all unused dependencies
tidy:
	make clean
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

# Build docker containers and run them (also generates new certificates)
docker_all:
	./docker/dockerize.sh -u -b -f

# Run docker containers
docker_up:
	./docker/dockerize.sh -u

# Build docker containers
docker_build:
	./docker/dockerize.sh -b

# Takes down docker containers
docker_down:
	./docker/dockerize.sh -d

# Cleans docker containers and certificates
docker_clean:
	make docker_down
	./docker/dockerize.sh -x
	docker volume rm osctrl_db-data
	rm -Rf docker/certs/*
	rm -Rf docker/config/*

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

gofmt-pkgs:
	gofmt $(GOFMT_ARGS) ./$(PKGS_DIR)

gofmt-plugins:
	gofmt $(GOFMT_ARGS) ./$(PLUGINS_DIR)

# Run all tests
test:
	# Install dependencies for TLS
	cd $(TLS_DIR) && go test -i . -v
	# Run TLS tests
	cd $(TLS_DIR) && go test . -v
	# Install dependencies for Admin
	cd $(ADMIN_DIR) && go test -i . -v
	# Run Admin tests
	cd $(ADMIN_DIR) && go test . -v
	# Install dependencies for API
	cd $(API_DIR) && go test -i . -v
	# Run API tests
	cd $(API_DIR) && go test . -v
	# Install dependencies for CLI
	cd $(CLI_DIR) && go test -i . -v
	# Run CLI tests
	cd $(CLI_DIR) && go test . -v
