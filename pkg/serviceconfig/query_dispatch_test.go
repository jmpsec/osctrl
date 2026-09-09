package serviceconfig

import (
	"fmt"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestUpdateSectionQueryDispatchTTL(t *testing.T) {
	for _, value := range []string{`1e30`, `"2m"`, `true`, `1.5`, `9223372036854775808`, `-9223372036854775809`, `{}`, `[]`} {
		t.Run("reject/"+value, func(t *testing.T) {
			m := &ServiceConfigManager{DB: setupTestDB(t)}
			require.NoError(t, m.Seed(config.ServiceTLS, testTLSParams(), 0))
			before, err := m.GetSection(config.ServiceTLS, "osquery", 0)
			require.NoError(t, err)
			_, err = m.UpdateSection(config.ServiceTLS, "osquery", `{"QueryDispatchTTL":`+value+`}`, 0)
			require.Error(t, err)
			after, err := m.GetSection(config.ServiceTLS, "osquery", 0)
			require.NoError(t, err)
			require.Equal(t, before.Value, after.Value)
			require.Equal(t, before.Source, after.Source)
			require.NoError(t, m.Resolve(config.ServiceTLS, testTLSParams(), 0))
		})
	}
	for _, duration := range []time.Duration{0, -1, 2 * time.Minute, 1<<63 - 1, -1 << 63} {
		t.Run(fmt.Sprintf("roundtrip/%d", duration), func(t *testing.T) {
			m := &ServiceConfigManager{DB: setupTestDB(t)}
			require.NoError(t, m.Seed(config.ServiceTLS, testTLSParams(), 0))
			value := fmt.Sprintf(`{"queryDispatchTTL":%d}`, duration)
			_, err := m.UpdateSection(config.ServiceTLS, "osquery", value, 0)
			require.NoError(t, err)
			params := testTLSParams()
			require.NoError(t, m.Resolve(config.ServiceTLS, params, 0))
			require.Equal(t, duration, params.Osquery.QueryDispatchTTL)
			stored, err := m.GetSection(config.ServiceTLS, "osquery", 0)
			require.NoError(t, err)
			require.JSONEq(t, value, stored.Value)
		})
	}
}
