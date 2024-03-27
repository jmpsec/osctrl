module environments

go 1.21

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/queries => ../queries

replace github.com/jmpsec/osctrl/types => ../types

replace github.com/jmpsec/osctrl/settings => ../settings

replace github.com/jmpsec/osctrl/utils => ../utils

replace github.com/jmpsec/osctrl/version => ../version

require (
	github.com/google/uuid v1.6.0
	github.com/jmpsec/osctrl/settings v0.0.0-20240327104847-8f8749e1bf8c
	github.com/jmpsec/osctrl/utils v0.0.0-20240327104917-8f400f8f2808
	github.com/jmpsec/osctrl/version v0.0.0-20240327104917-8f400f8f2808
	github.com/segmentio/ksuid v1.0.4
	github.com/stretchr/testify v1.9.0
	gorm.io/gorm v1.25.8
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmpsec/osctrl/nodes v0.3.5 // indirect
	github.com/jmpsec/osctrl/queries v0.3.5 // indirect
	github.com/jmpsec/osctrl/types v0.0.0-20240327104847-8f8749e1bf8c // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
