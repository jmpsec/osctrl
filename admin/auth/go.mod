module admin/auth

go 1.20

replace github.com/jmpsec/osctrl/admin/sessions => ../../admin/sessions

replace github.com/jmpsec/osctrl/environments => ../../environments

replace github.com/jmpsec/osctrl/nodes => ../../nodes

replace github.com/jmpsec/osctrl/queries => ../../queries

replace github.com/jmpsec/osctrl/settings => ../../settings

replace github.com/jmpsec/osctrl/types => ../../types

replace github.com/jmpsec/osctrl/users => ../../users

replace github.com/jmpsec/osctrl/utils => ../../utils

replace github.com/jmpsec/osctrl/version => ../../version

require (
	github.com/jmpsec/osctrl/admin/sessions v0.3.3
	github.com/jmpsec/osctrl/settings v0.3.3
	github.com/jmpsec/osctrl/users v0.3.3
)

require (
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/google/uuid v1.4.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/gorilla/sessions v1.2.2 // indirect
	github.com/jinzhu/gorm v1.9.16 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmpsec/osctrl/environments v0.3.3 // indirect
	github.com/jmpsec/osctrl/nodes v0.3.3 // indirect
	github.com/jmpsec/osctrl/queries v0.3.3 // indirect
	github.com/jmpsec/osctrl/types v0.3.3 // indirect
	github.com/jmpsec/osctrl/utils v0.3.3 // indirect
	github.com/jmpsec/osctrl/version v0.3.3 // indirect
	github.com/lib/pq v1.10.4 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	golang.org/x/crypto v0.15.0 // indirect
	gorm.io/gorm v1.25.5 // indirect
)
