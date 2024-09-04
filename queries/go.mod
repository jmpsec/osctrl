module github.com/jmpsec/osctrl/queries

go 1.23

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/utils => ../utils

require (
	github.com/jmpsec/osctrl/nodes v0.0.0-20240904183539-155969b2e259
	github.com/jmpsec/osctrl/utils v0.0.0-20240904183539-155969b2e259
	gorm.io/gorm v1.25.11
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	golang.org/x/text v0.18.0 // indirect
)
