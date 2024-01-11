module admin/sessions

go 1.21

replace github.com/jmpsec/osctrl/environments => ../../environments

replace github.com/jmpsec/osctrl/nodes => ../../nodes

replace github.com/jmpsec/osctrl/queries => ../../queries

replace github.com/jmpsec/osctrl/types => ../../types

replace github.com/jmpsec/osctrl/settings => ../../settings

replace github.com/jmpsec/osctrl/users => ../../users

replace github.com/jmpsec/osctrl/utils => ../../utils

replace github.com/jmpsec/osctrl/version => ../../version

require (
	github.com/gorilla/securecookie v1.1.2
	github.com/gorilla/sessions v1.2.2
	github.com/jmpsec/osctrl/nodes v0.3.4 // indirect
	github.com/jmpsec/osctrl/queries v0.3.4 // indirect
	github.com/jmpsec/osctrl/types v0.3.4 // indirect
	github.com/jmpsec/osctrl/users v0.3.4
)

require (
	github.com/jmpsec/osctrl/utils v0.0.0-20231221224851-87ae6d485538
	gorm.io/gorm v1.25.5
)

require (
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/google/uuid v1.5.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmpsec/osctrl/environments v0.0.0-20231221224851-87ae6d485538 // indirect
	github.com/jmpsec/osctrl/settings v0.3.4 // indirect
	github.com/jmpsec/osctrl/version v0.3.4 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	golang.org/x/crypto v0.17.0 // indirect
)
