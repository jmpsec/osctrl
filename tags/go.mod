module tags

go 1.17

require (
	github.com/jinzhu/gorm v1.9.16
	github.com/jmpsec/osctrl/nodes v0.0.0-20220119235714-4060db501cca
)

require github.com/jinzhu/inflection v1.0.0 // indirect

replace github.com/jmpsec/osctrl/nodes => ../nodes
