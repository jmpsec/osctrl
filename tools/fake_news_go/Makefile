GO ?= go

TLS_URL ?= http://localhost:9000
API_URL ?=
API_USERNAME ?=
API_PASSWORD ?=
DISCOVER_ENVS ?= 0
ENV_UUID ?=
SECRET ?=
NODES ?= 50
STATUS ?= 60
RESULT ?= 60
CONFIG ?= 45
QUERY ?= 30
STATE ?= fake_news_state.json
ERROR_THRESHOLD ?= 0.02
P95_THRESHOLD ?= 1s
SWEEP_START_NODES ?= 25
SWEEP_STEP_NODES ?= 25
SWEEP_STAGES ?= 8
SETTLE ?= 10s
SAMPLE ?= 20s
REPORT ?= fake_news_report.json

COMMON_ARGS = \
	--tls-url $(TLS_URL) \
	--env $(ENV_UUID) \
	--secret $(SECRET) \
	--nodes $(NODES) \
	--status $(STATUS) \
	--result $(RESULT) \
	--config $(CONFIG) \
	--query $(QUERY) \
	--state $(STATE)

ifneq ($(strip $(API_URL)),)
COMMON_ARGS += --api-url $(API_URL)
endif

ifneq ($(strip $(API_USERNAME)),)
COMMON_ARGS += --api-username $(API_USERNAME)
endif

ifneq ($(strip $(API_PASSWORD)),)
COMMON_ARGS += --api-password $(API_PASSWORD)
endif

ifeq ($(strip $(DISCOVER_ENVS)),1)
COMMON_ARGS += --discover-envs
endif

.PHONY: help dashboard sweep clean

help:
	@echo "fake_news_go helper targets"
	@echo ""
	@echo "Targets:"
	@echo "  make dashboard ENV_UUID=<uuid> SECRET=<secret> [NODES=50]"
	@echo "  make dashboard DISCOVER_ENVS=1 API_URL=http://localhost:9002 API_USERNAME=admin API_PASSWORD=admin"
	@echo "  make sweep ENV_UUID=<uuid> SECRET=<secret> [API_URL=http://localhost:9002]"
	@echo "  make sweep DISCOVER_ENVS=1 API_URL=http://localhost:9002 API_USERNAME=admin API_PASSWORD=admin"
	@echo "  make clean"
	@echo ""
	@echo "Common variables:"
	@echo "  TLS_URL=$(TLS_URL)"
	@echo "  API_URL=$(API_URL)"
	@echo "  NODES=$(NODES)"
	@echo "  STATE=$(STATE)"
	@echo "  SWEEP_START_NODES=$(SWEEP_START_NODES)"
	@echo "  SWEEP_STEP_NODES=$(SWEEP_STEP_NODES)"
	@echo "  SWEEP_STAGES=$(SWEEP_STAGES)"

dashboard:
	@if [ "$(DISCOVER_ENVS)" = "1" ]; then \
		test -n "$(API_URL)" || { echo "API_URL is required when DISCOVER_ENVS=1"; exit 1; }; \
		test -n "$(API_USERNAME)" || { echo "API_USERNAME is required when DISCOVER_ENVS=1"; exit 1; }; \
		test -n "$(API_PASSWORD)" || { echo "API_PASSWORD is required when DISCOVER_ENVS=1"; exit 1; }; \
	else \
		test -n "$(ENV_UUID)" || { echo "ENV_UUID is required"; exit 1; }; \
		test -n "$(SECRET)" || { echo "SECRET is required"; exit 1; }; \
	fi
	$(GO) run . $(COMMON_ARGS) --display-mode dashboard

sweep:
	@if [ "$(DISCOVER_ENVS)" = "1" ]; then \
		test -n "$(API_URL)" || { echo "API_URL is required when DISCOVER_ENVS=1"; exit 1; }; \
		test -n "$(API_USERNAME)" || { echo "API_USERNAME is required when DISCOVER_ENVS=1"; exit 1; }; \
		test -n "$(API_PASSWORD)" || { echo "API_PASSWORD is required when DISCOVER_ENVS=1"; exit 1; }; \
	else \
		test -n "$(ENV_UUID)" || { echo "ENV_UUID is required"; exit 1; }; \
		test -n "$(SECRET)" || { echo "SECRET is required"; exit 1; }; \
	fi
	$(GO) run . $(COMMON_ARGS) \
		--mode sweep \
		--display-mode dashboard \
		--error-threshold $(ERROR_THRESHOLD) \
		--p95-threshold $(P95_THRESHOLD) \
		--sweep-start-nodes $(SWEEP_START_NODES) \
		--sweep-step-nodes $(SWEEP_STEP_NODES) \
		--sweep-stages $(SWEEP_STAGES) \
		--settle $(SETTLE) \
		--sample $(SAMPLE)

clean:
	rm -f "$(STATE)" "$(REPORT)"
