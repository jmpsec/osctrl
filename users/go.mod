module github.com/jmpsec/osctrl/users

go 1.23

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/queries => ../queries

replace github.com/jmpsec/osctrl/types => ../types

replace github.com/jmpsec/osctrl/environments => ../environments

replace github.com/jmpsec/osctrl/users => ../users

replace github.com/jmpsec/osctrl/utils => ../utils

replace github.com/jmpsec/osctrl/settings => ../settings

replace github.com/jmpsec/osctrl/version => ../version

require (
	github.com/DATA-DOG/go-sqlmock v1.5.0
	github.com/golang-jwt/jwt/v4 v4.5.1
	github.com/jmpsec/osctrl/environments v0.0.0-20250203202337-3998cdcbfbca
	github.com/jmpsec/osctrl/types v0.0.0-20250203202337-3998cdcbfbca
	github.com/jmpsec/osctrl/utils v0.0.0-20250203202337-3998cdcbfbca
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.32.0
	gorm.io/driver/postgres v1.4.5
	gorm.io/gorm v1.25.12
)

require (
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.14.3 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.3 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/pgtype v1.14.0 // indirect
	github.com/jackc/pgx/v4 v4.18.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmpsec/osctrl/nodes v0.4.2 // indirect
	github.com/jmpsec/osctrl/queries v0.4.2 // indirect
	github.com/jmpsec/osctrl/settings v0.4.2 // indirect
	github.com/jmpsec/osctrl/version v0.4.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rs/zerolog v1.33.0
	github.com/segmentio/ksuid v1.0.4 // indirect
	golang.org/x/text v0.21.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
