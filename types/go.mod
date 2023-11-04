module types

go 1.20

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/queries => ../queries

replace github.com/jmpsec/osctrl/utils => ../utils

require github.com/jmpsec/osctrl/queries v0.3.3

require (
	github.com/google/uuid v1.4.0 // indirect
	github.com/jinzhu/gorm v1.9.16 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmpsec/osctrl/nodes v0.3.3 // indirect
	github.com/jmpsec/osctrl/utils v0.0.0-20231104125212-d6ff03b91b7b // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	gorm.io/gorm v1.25.5 // indirect
)
