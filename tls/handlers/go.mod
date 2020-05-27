module github.com/javuto/osctrl/tls/handlers

go 1.14

require (
	github.com/gorilla/mux v1.6.2
	github.com/jmpsec/osctrl/carves v0.2.2
	github.com/jmpsec/osctrl/environments v0.2.2
	github.com/jmpsec/osctrl/logging v0.2.2
	github.com/jmpsec/osctrl/metrics v0.2.2
	github.com/jmpsec/osctrl/nodes v0.2.2
	github.com/jmpsec/osctrl/queries v0.2.2
	github.com/jmpsec/osctrl/settings v0.2.2
	github.com/jmpsec/osctrl/types v0.2.2
	github.com/jmpsec/osctrl/utils v0.2.2
	github.com/segmentio/ksuid v1.0.2
	github.com/stretchr/testify v1.5.1
)

replace github.com/jmpsec/osctrl/carves => ../../carves

replace github.com/jmpsec/osctrl/environments => ../../environments

replace github.com/jmpsec/osctrl/logging => ../../logging

replace github.com/jmpsec/osctrl/metrics => ../../metrics

replace github.com/jmpsec/osctrl/nodes => ../../nodes

replace github.com/jmpsec/osctrl/queries => ../../queries

replace github.com/jmpsec/osctrl/settings => ../../settings

replace github.com/jmpsec/osctrl/types => ../../types

replace github.com/jmpsec/osctrl/utils => ../../utils
