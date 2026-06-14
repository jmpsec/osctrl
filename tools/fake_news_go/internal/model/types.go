package model

type Node struct {
	Target     string `json:"target"`
	IP         string `json:"ip"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Identifier string `json:"identifier"`
	Key        string `json:"key"`
}

type EndpointKind string

const (
	EndpointTLSEnroll EndpointKind = "tls/enroll"
	EndpointTLSLog    EndpointKind = "tls/log"
	EndpointTLSConfig EndpointKind = "tls/config"
	EndpointTLSRead   EndpointKind = "tls/read"
	EndpointTLSWrite  EndpointKind = "tls/write"
	EndpointAPILogin  EndpointKind = "api/login"
	EndpointAPIMe     EndpointKind = "api/users/me"
	EndpointAPIEnvs   EndpointKind = "api/environments"
	EndpointAPINodes  EndpointKind = "api/nodes"
	EndpointAPIConfig EndpointKind = "api/settings"
)
