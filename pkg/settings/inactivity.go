package settings

import (
	"fmt"
	"math"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
)

const MaxInactiveHours int64 = math.MaxInt64 / int64(time.Hour)

type InactivityPolicy struct {
	OverrideHours *int64 `json:"override_hours" extensions:"x-nullable" minimum:"1" maximum:"2562047"`
	InactiveHours int64  `json:"inactive_hours" minimum:"1" maximum:"2562047"`
	Source        string `json:"source" enums:"environment,global,default"`
}

func ValidateInactiveHours(hours int64) error {
	if hours < 1 || hours > MaxInactiveHours {
		return fmt.Errorf("inactive_hours must be an integer between 1 and %d", MaxInactiveHours)
	}
	return nil
}

// InactivityPolicy reads both scopes together; invalid legacy rows inherit.
func (conf *Settings) InactivityPolicy(envID uint) (InactivityPolicy, error) {
	policy := InactivityPolicy{InactiveHours: DefaultInactiveHours, Source: "default"}
	var values []SettingValue
	err := conf.DB.Where("service = ? AND name = ? AND environment_id IN ?", config.ServiceAPI, InactiveHours, []uint{NoEnvironmentID, envID}).
		Order("environment_id DESC, id ASC").Find(&values).Error
	if err != nil {
		return policy, err
	}
	for _, value := range values {
		if value.Type != TypeInteger || ValidateInactiveHours(value.Integer) != nil {
			continue
		}
		policy.InactiveHours = value.Integer
		policy.Source = "global"
		if value.EnvironmentID != NoEnvironmentID {
			policy.Source = "environment"
			policy.OverrideHours = &value.Integer
		}
		break
	}
	return policy, nil
}
