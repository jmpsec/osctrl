module carves

go 1.17

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/queries => ../queries

replace github.com/jmpsec/osctrl/types => ../types

require (
	github.com/jinzhu/gorm v1.9.16
	github.com/jmpsec/osctrl/nodes v0.0.0-20220120232002-31ecf3b9f264 // indirect
	github.com/jmpsec/osctrl/queries v0.2.9 // indirect
	github.com/jmpsec/osctrl/types v0.0.0-20220120232002-31ecf3b9f264
)

require github.com/jinzhu/inflection v1.0.0 // indirect
