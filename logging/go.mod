module logging

go 1.17

replace github.com/jmpsec/osctrl/backend => ../backend

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/queries => ../queries

replace github.com/jmpsec/osctrl/settings => ../settings

replace github.com/jmpsec/osctrl/types => ../types

replace github.com/jmpsec/osctrl/utils => ../utils

require (
	github.com/jinzhu/gorm v1.9.16
	github.com/jmpsec/osctrl/backend v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/nodes v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/queries v0.2.6
	github.com/jmpsec/osctrl/settings v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/types v0.0.0-20220120232002-31ecf3b9f264
	github.com/jmpsec/osctrl/utils v0.0.0-20220120232002-31ecf3b9f264
	github.com/spf13/viper v1.10.1
)

require (
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/lib/pq v1.10.4 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/spf13/afero v1.8.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9 // indirect
	golang.org/x/text v0.3.7 // indirect
	gopkg.in/ini.v1 v1.66.3 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
