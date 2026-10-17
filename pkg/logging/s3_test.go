package logging

import (
	"context"
	"path/filepath"
	"testing"

	osctrl_config "github.com/jmpsec/osctrl/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestCreateLoggerS3UsesStaticKeysOnlyWhenConfigured(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("AWS_CONFIG_FILE", missing)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", missing)
	t.Setenv("AWS_ACCESS_KEY_ID", "ENVKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ENVSECRET")

	tests := []struct {
		name       string
		access     string
		secret     string
		wantKey    string
		wantSecret string
		wantErr    bool
	}{
		{name: "no static keys falls back to default chain", wantKey: "ENVKEY", wantSecret: "ENVSECRET"},
		{name: "static keys", access: "STATICKEY", secret: "STATICSECRET", wantKey: "STATICKEY", wantSecret: "STATICSECRET"},
		{name: "only access key", access: "STATICKEY", wantErr: true},
		{name: "only secret key", secret: "STATICSECRET", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := CreateLoggerS3(&osctrl_config.S3Logger{
				Bucket:          "bucket",
				Region:          "us-east-1",
				AccessKey:       tt.access,
				SecretAccessKey: tt.secret,
			})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			creds, err := l.AWSConfig.Credentials.Retrieve(context.Background())
			require.NoError(t, err)
			require.Equal(t, tt.wantKey, creds.AccessKeyID)
			require.Equal(t, tt.wantSecret, creds.SecretAccessKey)
		})
	}
}
