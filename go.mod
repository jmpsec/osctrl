module osctrl

go 1.17

replace github.com/jmpsec/osctrl/admin/auth => ./admin/auth

replace github.com/jmpsec/osctrl/admin/handlers => ./admin/handlers

replace github.com/jmpsec/osctrl/admin/sessions => ./admin/sessions

replace github.com/jmpsec/osctrl/api/handlers => ./api/handlers

replace github.com/jmpsec/osctrl/backend => ./backend

replace github.com/jmpsec/osctrl/cache => ./cache

replace github.com/jmpsec/osctrl/carves => ./carves

replace github.com/jmpsec/osctrl/environments => ./environments

replace github.com/jmpsec/osctrl/logging => ./logging

replace github.com/jmpsec/osctrl/metrics => ./metrics

replace github.com/jmpsec/osctrl/nodes => ./nodes

replace github.com/jmpsec/osctrl/queries => ./queries

replace github.com/jmpsec/osctrl/settings => ./settings

replace github.com/jmpsec/osctrl/tags => ./tags

replace github.com/jmpsec/osctrl/tls/handlers => ./tls/handlers

replace github.com/jmpsec/osctrl/types => ./types

replace github.com/jmpsec/osctrl/users => ./users

replace github.com/jmpsec/osctrl/utils => ./utils

replace github.com/jmpsec/osctrl/version => ./version

require (
	github.com/crewjam/saml v0.4.9
	github.com/golang-jwt/jwt/v4 v4.4.2
	github.com/gorilla/mux v1.8.0
	github.com/jmpsec/osctrl/admin/handlers v0.3.1
	github.com/jmpsec/osctrl/admin/sessions v0.3.1
	github.com/jmpsec/osctrl/backend v0.3.1
	github.com/jmpsec/osctrl/cache v0.3.1
	github.com/jmpsec/osctrl/carves v0.3.1
	github.com/jmpsec/osctrl/environments v0.3.1
	github.com/jmpsec/osctrl/logging v0.3.1
	github.com/jmpsec/osctrl/metrics v0.3.1
	github.com/jmpsec/osctrl/nodes v0.3.1
	github.com/jmpsec/osctrl/queries v0.3.1
	github.com/jmpsec/osctrl/settings v0.3.1
	github.com/jmpsec/osctrl/tags v0.3.1
	github.com/jmpsec/osctrl/tls/handlers v0.3.1
	github.com/jmpsec/osctrl/types v0.3.1
	github.com/jmpsec/osctrl/users v0.3.1
	github.com/jmpsec/osctrl/utils v0.3.1
	github.com/jmpsec/osctrl/version v0.3.1
	github.com/olekukonko/tablewriter v0.0.5
	github.com/spf13/viper v1.13.0
	github.com/urfave/cli/v2 v2.23.0
	gorm.io/gorm v1.24.1-0.20221019064659-5dd2bb482755
)

require (
	github.com/aws/aws-sdk-go v1.42.44 // indirect
	github.com/aws/aws-sdk-go-v2 v1.16.11 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.4 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.17.1 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.12.14 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.12 // indirect
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.11.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.18 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.13.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.27.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.16.13 // indirect
	github.com/aws/smithy-go v1.12.1 // indirect
	github.com/beevik/etree v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/crewjam/httperr v0.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/go-redis/redis/v8 v8.11.4 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/gorilla/sessions v1.2.1 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.13.0 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.1 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/pgtype v1.12.0 // indirect
	github.com/jackc/pgx/v4 v4.17.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.4 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.0.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/rs/zerolog v1.26.1 // indirect
	github.com/russellhaering/goxmldsig v1.1.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	github.com/spf13/afero v1.8.2 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.4.1 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa // indirect
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a // indirect
	golang.org/x/term v0.1.0
	golang.org/x/text v0.3.7 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gorm.io/driver/postgres v1.4.5 // indirect
)
