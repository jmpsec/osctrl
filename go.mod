module osctrl

go 1.15

require (
	github.com/crewjam/saml v0.4.5
	github.com/golang-jwt/jwt/v4 v4.0.0
	github.com/gorilla/mux v1.8.0
	github.com/jinzhu/gorm v1.9.16
	github.com/jmpsec/osctrl/admin/handlers v0.2.5
	github.com/jmpsec/osctrl/admin/sessions v0.2.5
	github.com/jmpsec/osctrl/backend v0.2.5
	github.com/jmpsec/osctrl/carves v0.2.5
	github.com/jmpsec/osctrl/environments v0.2.5
	github.com/jmpsec/osctrl/logging v0.2.5
	github.com/jmpsec/osctrl/metrics v0.2.5
	github.com/jmpsec/osctrl/nodes v0.2.5
	github.com/jmpsec/osctrl/queries v0.2.5
	github.com/jmpsec/osctrl/settings v0.2.5
	github.com/jmpsec/osctrl/tags v0.2.5
	github.com/jmpsec/osctrl/tls/handlers v0.2.5
	github.com/jmpsec/osctrl/types v0.2.5
	github.com/jmpsec/osctrl/users v0.2.5
	github.com/jmpsec/osctrl/utils v0.2.5
	github.com/olekukonko/tablewriter v0.0.4
	github.com/spf13/viper v1.7.1
	github.com/urfave/cli v1.22.5
)

replace github.com/jmpsec/osctrl/backend => ./backend

replace github.com/jmpsec/osctrl/carves => ./carves

replace github.com/jmpsec/osctrl/environments => ./environments

replace github.com/jmpsec/osctrl/metrics => ./metrics

replace github.com/jmpsec/osctrl/nodes => ./nodes

replace github.com/jmpsec/osctrl/queries => ./queries

replace github.com/jmpsec/osctrl/settings => ./settings

replace github.com/jmpsec/osctrl/types => ./types

replace github.com/jmpsec/osctrl/users => ./users

replace github.com/jmpsec/osctrl/tags => ./tags

replace github.com/jmpsec/osctrl/utils => ./utils

replace github.com/jmpsec/osctrl/logging => ./logging

replace github.com/jmpsec/osctrl/tls/handlers => ./tls/handlers

replace github.com/jmpsec/osctrl/admin/handlers => ./admin/handlers

replace github.com/jmpsec/osctrl/admin/sessions => ./admin/sessions

replace github.com/jmpsec/osctrl/api/handlers => ./api/handlers
