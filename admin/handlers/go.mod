module github.com/javuto/osctrl/admin/handlers

go 1.15

require (
	github.com/gorilla/mux v1.7.4
	github.com/gorilla/sessions v1.2.0 // indirect
	github.com/jinzhu/gorm v1.9.12
	github.com/jmpsec/osctrl/admin/sessions v0.2.6
	github.com/jmpsec/osctrl/carves v0.2.6
	github.com/jmpsec/osctrl/environments v0.2.6
	github.com/jmpsec/osctrl/logging v0.2.6
	github.com/jmpsec/osctrl/metrics v0.2.6
	github.com/jmpsec/osctrl/nodes v0.2.6
	github.com/jmpsec/osctrl/queries v0.2.6
	github.com/jmpsec/osctrl/settings v0.2.6
	github.com/jmpsec/osctrl/tags v0.2.6
	github.com/jmpsec/osctrl/types v0.2.6
	github.com/jmpsec/osctrl/users v0.2.6
	github.com/jmpsec/osctrl/utils v0.2.6
)

replace github.com/jmpsec/osctrl/carves => ../../carves

replace github.com/jmpsec/osctrl/settings => ../../settings

replace github.com/jmpsec/osctrl/environments => ../../environments

replace github.com/jmpsec/osctrl/metrics => ../../metrics

replace github.com/jmpsec/osctrl/nodes => ../../nodes

replace github.com/jmpsec/osctrl/queries => ../../queries

replace github.com/jmpsec/osctrl/types => ../../types

replace github.com/jmpsec/osctrl/users => ../../users

replace github.com/jmpsec/osctrl/utils => ../../utils

replace github.com/jmpsec/osctrl/logging => ../../logging

replace github.com/jmpsec/osctrl/tls/handlers => ./tls/handlers

replace github.com/jmpsec/osctrl/admin/sessions => ../sessions
