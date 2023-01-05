module metrics

go 1.17

replace github.com/jmpsec/osctrl/types => ../types

replace github.com/jmpsec/osctrl/queries => ../queries

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/utils => ../utils

require (
	github.com/DATA-DOG/go-sqlmock v1.5.0
	github.com/spf13/viper v1.10.1
	github.com/test-go/testify v1.1.4
	gorm.io/driver/postgres v1.4.6
	gorm.io/gorm v1.24.3
)

require (
	github.com/google/uuid v1.3.0 // indirect
	github.com/jmpsec/osctrl/nodes v0.3.1 // indirect
	github.com/jmpsec/osctrl/utils v0.0.0-00010101000000-000000000000 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/pgx/v5 v5.2.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmpsec/osctrl/queries v0.3.1 // indirect
	github.com/jmpsec/osctrl/types v0.0.0-20220120232002-31ecf3b9f264
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/afero v1.8.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	golang.org/x/crypto v0.4.0 // indirect
	golang.org/x/sys v0.3.0 // indirect
	golang.org/x/text v0.5.0 // indirect
	gopkg.in/ini.v1 v1.66.3 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
