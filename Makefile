export GO111MODULE=on
export GOPROXY=https://proxy.golang.org,direct

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

DEST ?= /opt/osctrl

OUTPUT = bin
DIST = dist

STATIC_ARGS = -ldflags "-linkmode external -extldflags -static"
BUILD_ARGS = -ldflags "-s -w -X main.buildCommit=$(shell git rev-parse HEAD) -X main.buildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)"

.PHONY: build static clean tls admin cli api release release-build release-check release-init clean-dist

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
	go build $(BUILD_ARGS) -o $(OUTPUT)/$(TLS_NAME) $(TLS_CODE)

# Build TLS endpoint statically
tls-static:
	go build $(BUILD_ARGS) $(STATIC_ARGS) -o $(OUTPUT)/$(TLS_NAME) -a $(TLS_CODE)

# Build Admin UI
admin:
	go build $(BUILD_ARGS) -o $(OUTPUT)/$(ADMIN_NAME) $(ADMIN_CODE)

# Build Admin UI statically
admin-static:
	go build $(BUILD_ARGS) $(STATIC_ARGS) -o $(OUTPUT)/$(ADMIN_NAME) -a $(ADMIN_CODE)

# Build API
api:
	go build $(BUILD_ARGS) -o $(OUTPUT)/$(API_NAME) $(API_CODE)

# Build API statically
api-static:
	go build $(BUILD_ARGS) $(STATIC_ARGS) -o $(OUTPUT)/$(API_NAME) -a $(API_CODE)

# Build the CLI
cli:
	go build $(BUILD_ARGS) -o $(OUTPUT)/$(CLI_NAME) $(CLI_CODE)

# Build the CLI statically
cli-static:
	go build $(BUILD_ARGS) $(STATIC_ARGS) -o $(OUTPUT)/$(CLI_NAME) -a $(CLI_CODE)

# Clean the dist directory
clean-dist:
	rm -rf $(DIST)

# Delete all compiled binaries
clean:
	rm -rf $(OUTPUT)/$(TLS_NAME)
	rm -rf $(OUTPUT)/$(ADMIN_NAME)
	rm -rf $(OUTPUT)/$(API_NAME)
	rm -rf $(OUTPUT)/$(CLI_NAME)
	make clean-dist

# Dekete all dependencies go.sum files
clean_go:
	find . -name "go.sum" -type f -exec rm -rf {} \;

# Remove all unused dependencies
tidy:
	make clean
	make clean_go
	go mod tidy

# Keep dependencies up to date
deps-update:
ifeq (,$(wildcard go.mod))
	$(error Missing go.mod file)
endif
	go get -u ./...

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
	sudo rsync -av $(ADMIN_DIR)/templates/ $(DEST)/tmpl_admin
	sudo rsync -av $(ADMIN_DIR)/static/ $(DEST)/static
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

# Display docker logs for TLS server
docker_dev_logs_tls:
	docker logs -f $(TLS_NAME)-dev

# Display systemd logs for Admin server
logs_admin:
	sudo journalctl -f -t $(ADMIN_NAME)

# Display docker logs for Admin server
docker_dev_logs_admin:
	docker logs -f $(ADMIN_NAME)-dev

# Display systemd logs for API server
logs_api:
	sudo journalctl -f -t $(API_NAME)

# Display docker logs for API server
docker_dev_logs_api:
	docker logs -f $(API_NAME)-dev

# Display docker logs for nginx server
docker_dev_logs_nginx:
	docker logs -f osctrl-nginx-dev

# Display docker logs for osquery clients
docker_dev_logs_osquery-1:
	docker logs -f osctrl-osquery-1-dev

docker_dev_logs_osquery-2:
	docker logs -f osctrl-osquery-2-dev

docker_dev_logs_osquery-3:
	docker logs -f osctrl-osquery-3-dev

# Display docker logs for postgresql server
docker_dev_logs_postgresql:
	docker logs -f osctrl-postgres-dev

# Display docker logs for redis server
docker_dev_logs_redis:
	docker logs -f osctrl-redis-dev

# Docker shell into TLS server
docker_dev_shell_tls:
	docker exec -it $(TLS_NAME)-dev /bin/bash

# Docker shell into Admin server
docker_dev_shell_admin:
	docker exec -it $(ADMIN_NAME)-dev /bin/bash

# Docker shell into API server
docker_dev_shell_api:
	docker exec -it $(API_NAME)-dev /bin/bash

# Docker shell into osquery client
docker_dev_shell_osquery:
	docker exec -it osctrl-osquery-dev /bin/bash

# Docker shell into postgresql server
docker_dev_shell_postgres:
	docker exec -it osctrl-postgres-dev /bin/bash

# Docker shell into redis server
docker_dev_shell_redis:
	docker exec -it osctrl-redis-dev /bin/sh

# Build dev docker containers and run them (also generates new certificates)
docker_dev_build:
ifeq (,$(wildcard ./.env))
	$(error Missing .env file)
endif
ifeq (,$(wildcard ./deploy/docker/conf/tls/osctrl.crt))
	$(error Missing TLS certificate file)
endif
ifeq (,$(wildcard ./deploy/docker/conf/tls/osctrl.key))
	$(error Missing TLS private key file)
endif
	docker-compose -f docker-compose-dev.yml build --provenance=false

# Build and run dev docker containers
make docker_dev:
	make docker_dev_build
	make docker_dev_up

# Run docker containers
docker_dev_up:
	docker-compose -f docker-compose-dev.yml up

up-backend:
	docker-compose -f docker-compose-dev.yml up osctrl-postgres osctrl-redis

# Takes down docker containers
docker_dev_down:
	docker-compose -f docker-compose-dev.yml down

# Deletes all osctrl docker images and volumes
docker_dev_clean:
	docker images | grep osctrl | awk '{print $$3}' | xargs -rI {} docker rmi -f {}
	docker volume ls | grep osctrl | awk '{print $$2}' | xargs -rI {} docker volume rm {}

# Rebuild only the TLS server
docker_dev_rebuild_tls:
	docker-compose -f docker-compose-dev.yml up --force-recreate --no-deps -d --build $(TLS_NAME)

# Rebuild only the Admin server
docker_dev_rebuild_admin:
	docker-compose -f docker-compose-dev.yml up --force-recreate --no-deps -d --build $(ADMIN_NAME)

# Rebuild only the CLI
docker_dev_rebuild_cli:
	docker-compose -f docker-compose-dev.yml up --force-recreate --no-deps -d --build $(CLI_NAME)

# Rebuild only the API server
docker_dev_rebuild_api:
	docker-compose -f docker-compose-dev.yml up --force-recreate --no-deps -d --build $(API_NAME)

# Deploy osctrl in a single server using the provision.sh script
provision_dev:
	./deploy/provision.sh -m prod -s /home/$(DEV_USER)/osctrl -t self -p all --nginx --postgres -E -R --tls-hostname "$(DEV_IP)" --admin-hostname "$(DEV_IP)" --api-hostname "$(DEV_IP)" -X admin

# Run linter
lint:
	golangci-lint run

# Run all tests
test:
	go clean -testcache ./...
	go test ./utils -v
	go test ./cmd/tls/handlers -v

# Check test coverage
test_cover:
	cd utils && go test -cover .
	cd cmd/tls/handlers && go test -cover .

# Build snapshot binaries with GoReleaser
release-build:
	make clean-dist
	./tools/gorelease.sh build

# Check GoReleaser configuration
release-check:
	./tools/gorelease.sh check

# Initialize GoReleaser configuration
release-init:
	./tools/gorelease.sh init

# Create a release (requires tag)
release:
	make clean-dist
	./tools/gorelease.sh release

# Build and test release locally
release-test:
	make release-build
	@echo "Testing built binaries..."
	@for binary in $(DIST)/osctrl-*; do \
		if [ -f "$$binary" ] && [ -x "$$binary" ]; then \
			echo "Testing $$binary"; \
			$$binary --version || $$binary version || echo "No version flag available"; \
		fi; \
	done
