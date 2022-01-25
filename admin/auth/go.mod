module admin/auth

go 1.17

replace github.com/jmpsec/osctrl/admin/sessions => ../../admin/sessions

replace github.com/jmpsec/osctrl/nodes => ../../nodes

replace github.com/jmpsec/osctrl/queries => ../../queries

replace github.com/jmpsec/osctrl/settings => ../../settings

replace github.com/jmpsec/osctrl/types => ../../types

replace github.com/jmpsec/osctrl/users => ../../users

require (
	github.com/jmpsec/osctrl/admin/sessions v0.2.7
	github.com/jmpsec/osctrl/settings v0.2.7
	github.com/jmpsec/osctrl/users v0.2.7
)

require (
	github.com/golang-jwt/jwt/v4 v4.2.0 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/gorilla/sessions v1.2.1 // indirect
	github.com/jinzhu/gorm v1.9.16 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jmpsec/osctrl/nodes v0.2.7 // indirect
	github.com/jmpsec/osctrl/queries v0.2.7 // indirect
	github.com/jmpsec/osctrl/types v0.2.7 // indirect
	github.com/lib/pq v1.1.1 // indirect
	golang.org/x/crypto v0.0.0-20220112180741-5e0467b6c7ce // indirect
)
