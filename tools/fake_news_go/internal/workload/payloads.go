package workload

import "github.com/jmpsec/osctrl/tools/fake_news_go/internal/config"

type APILoginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	ExpHours int    `json:"exp_hours"`
}

func NewAPILoginPayload(cfg config.Config) APILoginPayload {
	return APILoginPayload{
		Username: cfg.APIUsername,
		Password: cfg.APIPassword,
		ExpHours: 24,
	}
}
