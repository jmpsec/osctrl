module admin/handlers

go 1.17

replace github.com/jmpsec/osctrl/admin/sessions => ../../admin/sessions

replace github.com/jmpsec/osctrl/backend => ../../backend

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

require (
	github.com/gorilla/mux v1.8.0
	github.com/jmpsec/osctrl/admin/sessions v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/backend v0.0.0-20220120232002-31ecf3b9f264 // indirect
	github.com/jmpsec/osctrl/carves v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/environments v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/logging v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/metrics v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/nodes v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/queries v0.3.0
	github.com/jmpsec/osctrl/settings v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/tags v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/types v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/users v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/utils v0.0.0-20220120232002-31ecf3b9f264
)

require (
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/golang-jwt/jwt/v4 v4.2.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/gorilla/sessions v1.2.1 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/lib/pq v1.10.4 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	github.com/spf13/afero v1.8.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.10.1 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	golang.org/x/crypto v0.0.0-20220112180741-5e0467b6c7ce // indirect
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9 // indirect
	golang.org/x/text v0.3.7 // indirect
	gopkg.in/ini.v1 v1.66.3 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
