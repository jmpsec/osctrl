module github.com/javuto/osctrl

go 1.12

require (
	github.com/beevik/etree v1.1.0 // indirect
	github.com/crewjam/saml v0.0.0-20180831135026-ebc5f787b786 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/gorilla/mux v1.7.0 // indirect
	github.com/gorilla/sessions v1.1.3 // indirect
	github.com/javuto/osctrl/carves v0.0.0-00010101000000-000000000000 // indirect
	github.com/javuto/osctrl/configuration v0.0.0-00010101000000-000000000000 // indirect
	github.com/javuto/osctrl/context v0.0.0-00010101000000-000000000000 // indirect
	github.com/javuto/osctrl/metrics v0.0.0-00010101000000-000000000000 // indirect
	github.com/javuto/osctrl/nodes v0.0.0-00010101000000-000000000000 // indirect
	github.com/javuto/osctrl/queries v0.0.0-00010101000000-000000000000 // indirect
	github.com/javuto/osctrl/users v0.0.0-00010101000000-000000000000 // indirect
	github.com/jinzhu/gorm v1.9.2 // indirect
	github.com/jinzhu/inflection v0.0.0-20180308033659-04140366298a // indirect
	github.com/jonboulle/clockwork v0.1.0 // indirect
	github.com/lib/pq v1.0.0 // indirect
	github.com/russellhaering/goxmldsig v0.0.0-20180430223755-7acd5e4a6ef7 // indirect
	github.com/segmentio/ksuid v1.0.2 // indirect
	github.com/spf13/viper v1.3.2 // indirect
	github.com/urfave/cli v1.20.0 // indirect
)

replace github.com/javuto/osctrl/carves => ./pkg/carves

replace github.com/javuto/osctrl/configuration => ./pkg/configuration

replace github.com/javuto/osctrl/context => ./pkg/context

replace github.com/javuto/osctrl/metrics => ./pkg/metrics

replace github.com/javuto/osctrl/nodes => ./pkg/nodes

replace github.com/javuto/osctrl/queries => ./pkg/queries

replace github.com/javuto/osctrl/users => ./pkg/users
