module osctrl

go 1.15

require (
	github.com/bketelsen/crypt v0.0.5 // indirect
	github.com/coreos/etcd v3.3.13+incompatible // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.1 // indirect
	github.com/crewjam/saml v0.4.6
	github.com/golang-jwt/jwt/v4 v4.2.0
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/sessions v1.2.1 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/hashicorp/go.net v0.0.1 // indirect
	github.com/jinzhu/gorm v1.9.16
	github.com/jmpsec/osctrl/admin/handlers v0.2.6
	github.com/jmpsec/osctrl/admin/sessions v0.2.6
	github.com/jmpsec/osctrl/backend v0.2.6
	github.com/jmpsec/osctrl/carves v0.2.6
	github.com/jmpsec/osctrl/environments v0.2.6
	github.com/jmpsec/osctrl/logging v0.2.6
	github.com/jmpsec/osctrl/metrics v0.2.6
	github.com/jmpsec/osctrl/nodes v0.2.6
	github.com/jmpsec/osctrl/queries v0.2.6
	github.com/jmpsec/osctrl/settings v0.2.6
	github.com/jmpsec/osctrl/tags v0.2.6
	github.com/jmpsec/osctrl/tls/handlers v0.2.6
	github.com/jmpsec/osctrl/types v0.2.6
	github.com/jmpsec/osctrl/users v0.2.6
	github.com/jmpsec/osctrl/utils v0.2.6
	github.com/lib/pq v1.10.4 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mitchellh/gox v0.4.0 // indirect
	github.com/mitchellh/iochan v1.0.0 // indirect
	github.com/olekukonko/tablewriter v0.0.5
	github.com/segmentio/ksuid v1.0.4 // indirect
	github.com/spf13/afero v1.7.1 // indirect
	github.com/spf13/viper v1.10.1
	github.com/stretchr/objx v0.3.0 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/urfave/cli v1.22.5
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3 // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
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
