package workload

import (
	"strings"

	"github.com/jmpsec/osctrl/tools/fake_news_go/internal/config"
	"github.com/jmpsec/osctrl/tools/fake_news_go/internal/model"
)

const (
	GroupTLS = "tls"
	GroupAPI = "api"
)

type Scenario struct {
	Name         string
	Group        string
	Endpoint     model.EndpointKind
	Method       string
	PathTemplate string
	AuthRequired bool
	Enabled      bool
}

func BuildDefaultScenarios(cfg config.Config) []Scenario {
	scenarios := []Scenario{
		{Name: "tls-enroll", Group: GroupTLS, Endpoint: model.EndpointTLSEnroll, Method: "POST", PathTemplate: "/enroll", Enabled: true},
		{Name: "tls-status-log", Group: GroupTLS, Endpoint: model.EndpointTLSLog, Method: "POST", PathTemplate: "/log", Enabled: true},
		{Name: "tls-result-log", Group: GroupTLS, Endpoint: model.EndpointTLSLog, Method: "POST", PathTemplate: "/log", Enabled: true},
		{Name: "tls-config", Group: GroupTLS, Endpoint: model.EndpointTLSConfig, Method: "POST", PathTemplate: "/config", Enabled: true},
		{Name: "tls-query-read", Group: GroupTLS, Endpoint: model.EndpointTLSRead, Method: "POST", PathTemplate: "/read", Enabled: true},
		{Name: "tls-query-write", Group: GroupTLS, Endpoint: model.EndpointTLSWrite, Method: "POST", PathTemplate: "/write", Enabled: true},
	}

	if strings.TrimSpace(cfg.APIBaseURL) == "" {
		return scenarios
	}

	scenarios = append(scenarios,
		Scenario{Name: "api-auth-methods", Group: GroupAPI, Endpoint: model.EndpointAPILogin, Method: "GET", PathTemplate: "/api/v1/auth/methods", Enabled: true},
		Scenario{Name: "api-login-environments", Group: GroupAPI, Endpoint: model.EndpointAPIEnvs, Method: "GET", PathTemplate: "/api/v1/login/environments", Enabled: true},
	)

	if !hasAPICredentials(cfg) {
		return scenarios
	}

	scenarios = append(scenarios,
		Scenario{Name: "api-login", Group: GroupAPI, Endpoint: model.EndpointAPILogin, Method: "POST", PathTemplate: "/api/v1/login", Enabled: true},
		Scenario{Name: "api-users-me", Group: GroupAPI, Endpoint: model.EndpointAPIMe, Method: "GET", PathTemplate: "/api/v1/users/me", AuthRequired: true, Enabled: true},
		Scenario{Name: "api-environments", Group: GroupAPI, Endpoint: model.EndpointAPIEnvs, Method: "GET", PathTemplate: "/api/v1/environments", AuthRequired: true, Enabled: true},
		Scenario{Name: "api-environment-detail", Group: GroupAPI, Endpoint: model.EndpointAPIEnvs, Method: "GET", PathTemplate: "/api/v1/environments/{env}", AuthRequired: true, Enabled: true},
		Scenario{Name: "api-nodes-paged", Group: GroupAPI, Endpoint: model.EndpointAPINodes, Method: "GET", PathTemplate: "/api/v1/nodes/{env}?status=all&page=1&page_size=50&sort=lastseen&dir=desc", AuthRequired: true, Enabled: true},
		Scenario{Name: "api-node-detail", Group: GroupAPI, Endpoint: model.EndpointAPINodes, Method: "GET", PathTemplate: "/api/v1/nodes/{env}/node/{node}", AuthRequired: true, Enabled: true},
		Scenario{Name: "api-settings", Group: GroupAPI, Endpoint: model.EndpointAPIConfig, Method: "GET", PathTemplate: "/api/v1/settings/api/{env}", AuthRequired: true, Enabled: true},
	)

	return scenarios
}

func hasAPICredentials(cfg config.Config) bool {
	return strings.TrimSpace(cfg.APIUsername) != "" && strings.TrimSpace(cfg.APIPassword) != ""
}
