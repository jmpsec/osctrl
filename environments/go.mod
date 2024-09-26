module github.com/jmpsec/osctrl/environments

go 1.23

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/queries => ../queries

replace github.com/jmpsec/osctrl/types => ../types

replace github.com/jmpsec/osctrl/settings => ../settings

replace github.com/jmpsec/osctrl/utils => ../utils

replace github.com/jmpsec/osctrl/version => ../version

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/jmpsec/osctrl/settings v0.0.0-20240926110606-74392bf45499
	github.com/jmpsec/osctrl/utils v0.0.0-20240904183539-155969b2e259
	github.com/jmpsec/osctrl/version v0.0.0-20240904183539-155969b2e259
	github.com/segmentio/ksuid v1.0.4 // indirect
	github.com/stretchr/testify v1.9.0
	gorm.io/gorm v1.25.11
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmpsec/osctrl/nodes v0.3.9 // indirect
	github.com/jmpsec/osctrl/queries v0.3.9 // indirect
	github.com/jmpsec/osctrl/types v0.0.0-20240904183539-155969b2e259 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rs/zerolog v1.33.0 // indirect
	golang.org/x/sys v0.12.0 // indirect
	golang.org/x/text v0.18.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
