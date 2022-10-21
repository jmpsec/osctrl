module types

go 1.17

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/queries => ../queries

require github.com/jmpsec/osctrl/queries v0.3.1

require (
	github.com/jinzhu/gorm v1.9.16 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jmpsec/osctrl/nodes v0.3.1 // indirect
)
