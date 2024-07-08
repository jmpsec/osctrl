module admin/handlers

go 1.21

replace github.com/jmpsec/osctrl/admin/sessions => ../../admin/sessions

replace github.com/jmpsec/osctrl/backend => ../../backend

replace github.com/jmpsec/osctrl/cache => ../../cache

replace github.com/jmpsec/osctrl/carves => ../../carves

replace github.com/jmpsec/osctrl/environments => ../../environments

replace github.com/jmpsec/osctrl/logging => ../../logging

replace github.com/jmpsec/osctrl/metrics => ../../metrics

replace github.com/jmpsec/osctrl/nodes => ../../nodes

replace github.com/jmpsec/osctrl/queries => ../../queries

replace github.com/jmpsec/osctrl/settings => ../../settings

replace github.com/jmpsec/osctrl/tags => ../../tags

replace github.com/jmpsec/osctrl/types => ../../types

replace github.com/jmpsec/osctrl/users => ../../users

replace github.com/jmpsec/osctrl/utils => ../../utils

replace github.com/jmpsec/osctrl/version => ../../version

require (
	github.com/gorilla/mux v1.8.1
	github.com/jmpsec/osctrl/admin/sessions v0.3.7
	github.com/jmpsec/osctrl/carves v0.3.7
	github.com/jmpsec/osctrl/environments v0.0.0-20240704175315-b3e7d3dd0a86
	github.com/jmpsec/osctrl/metrics v0.0.0-20240704175315-b3e7d3dd0a86
	github.com/jmpsec/osctrl/nodes v0.3.7
	github.com/jmpsec/osctrl/queries v0.3.7
	github.com/jmpsec/osctrl/settings v0.3.7
	github.com/jmpsec/osctrl/tags v0.0.0-20240704175315-b3e7d3dd0a86
	github.com/jmpsec/osctrl/types v0.3.7
	github.com/jmpsec/osctrl/users v0.3.7
	github.com/jmpsec/osctrl/utils v0.3.7
)

require (
	github.com/jmpsec/osctrl/cache v0.0.0-20240704175315-b3e7d3dd0a86
	gorm.io/gorm v1.25.10
)

require (
	github.com/aws/aws-sdk-go v1.54.14 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/jmpsec/osctrl/backend v0.3.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/rs/zerolog v1.33.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

require (
	github.com/aws/aws-sdk-go-v2 v1.30.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.3 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.27.24 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.24 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.9 // indirect
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.17.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.3.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.17.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.58.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.22.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.26.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.1 // indirect
	github.com/aws/smithy-go v1.20.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-redis/redis/v8 v8.11.5 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/gorilla/sessions v1.3.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/jackc/pgx/v5 v5.6.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jmpsec/osctrl/logging v0.0.0-20240704175315-b3e7d3dd0a86
	github.com/jmpsec/osctrl/version v0.3.7 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/sagikazarmark/locafero v0.6.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.19.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.24.0 // indirect
	golang.org/x/exp v0.0.0-20240613232115-7f521ea00fb8 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gorm.io/driver/postgres v1.5.9 // indirect
)
