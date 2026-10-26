package environments

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpdateBooleans(t *testing.T) {
	m := &EnvManager{DB: setupTestDB(t)}
	env := m.Empty("dev", "dev.example.com")
	env.DebugHTTP = true
	require.NoError(t, m.Create(&env))
	off, on := false, true
	get := func() TLSEnvironment { e, err := m.Get("dev"); require.NoError(t, err); return e }
	// false is written, nil leaves the column alone.
	require.NoError(t, m.UpdateBooleans("dev", &off, nil))
	require.False(t, get().DebugHTTP)
	require.True(t, get().AcceptEnrolls)
	require.NoError(t, m.UpdateBooleans(env.UUID, nil, &off))
	require.False(t, get().AcceptEnrolls)
	require.NoError(t, m.UpdateBooleans("dev", &on, &on))
	require.True(t, get().DebugHTTP)
	require.True(t, get().AcceptEnrolls)
	require.NoError(t, m.UpdateBooleans("dev", nil, nil))
}
