module github.com/jmpsec/osctrl/queries

go 1.21

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/utils => ../utils

require (
	github.com/jmpsec/osctrl/nodes v0.0.0-20240712215734-76cb76cf1447
	github.com/jmpsec/osctrl/utils v0.0.0-20240712215734-76cb76cf1447
	gorm.io/gorm v1.25.11
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	golang.org/x/text v0.16.0 // indirect
)
