module github.com/jmpsec/osctrl/settings

go 1.23

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/queries => ../queries

replace github.com/jmpsec/osctrl/types => ../types

replace github.com/jmpsec/osctrl/utils => ../utils

require (
	github.com/jmpsec/osctrl/types v0.0.0-20240819084417-5d0c74745216
	gorm.io/gorm v1.25.11
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmpsec/osctrl/nodes v0.0.0-20240819084417-5d0c74745216 // indirect
	github.com/jmpsec/osctrl/queries v0.0.0-20240819084417-5d0c74745216 // indirect
	github.com/jmpsec/osctrl/utils v0.0.0-20240819084417-5d0c74745216 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	golang.org/x/text v0.17.0 // indirect
)
