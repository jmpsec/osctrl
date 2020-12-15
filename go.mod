module github.com/jmpsec/osctrl

go 1.14

require (
	github.com/beevik/etree v1.1.0 // indirect
	github.com/crewjam/saml v0.0.0-20190508002657-ca21de9dd5b9
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gorilla/mux v1.7.4
	github.com/jinzhu/gorm v1.9.12
	github.com/jmpsec/osctrl/admin/handlers v0.2.3
	github.com/jmpsec/osctrl/admin/sessions v0.2.3
	github.com/jmpsec/osctrl/backend v0.2.3
	github.com/jmpsec/osctrl/carves v0.2.3
	github.com/jmpsec/osctrl/environments v0.2.3
	github.com/jmpsec/osctrl/logging v0.2.3
	github.com/jmpsec/osctrl/metrics v0.2.3
	github.com/jmpsec/osctrl/nodes v0.2.3
	github.com/jmpsec/osctrl/queries v0.2.3
	github.com/jmpsec/osctrl/settings v0.2.3
	github.com/jmpsec/osctrl/tags v0.2.3
	github.com/jmpsec/osctrl/tls/handlers v0.2.3
	github.com/jmpsec/osctrl/types v0.2.3
	github.com/jmpsec/osctrl/users v0.2.3
	github.com/jmpsec/osctrl/utils v0.2.3
	github.com/olekukonko/tablewriter v0.0.4
	github.com/russellhaering/goxmldsig v1.1.0 // indirect
	github.com/spf13/viper v1.6.2
	github.com/urfave/cli v1.22.4
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
