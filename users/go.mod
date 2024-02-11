module users

go 1.21

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
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/jmpsec/osctrl/environments v0.0.0-20231221224851-87ae6d485538
	github.com/jmpsec/osctrl/types v0.0.0-20231221224851-87ae6d485538
	github.com/jmpsec/osctrl/utils v0.0.0-20231221224851-87ae6d485538
	github.com/stretchr/testify v1.8.4
	golang.org/x/crypto v0.17.0
	gorm.io/driver/postgres v1.4.5
	gorm.io/gorm v1.25.5
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/uuid v1.5.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.13.0 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.1 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/pgtype v1.12.0 // indirect
	github.com/jackc/pgx/v4 v4.17.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmpsec/osctrl/nodes v0.3.5 // indirect
	github.com/jmpsec/osctrl/queries v0.3.5 // indirect
	github.com/jmpsec/osctrl/settings v0.3.5 // indirect
	github.com/jmpsec/osctrl/version v0.3.5 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	golang.org/x/text v0.14.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
