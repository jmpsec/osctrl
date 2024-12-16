module github.com/jmpsec/osctrl/admin/sessions

go 1.23

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
	github.com/gorilla/sessions v1.4.0
	github.com/jmpsec/osctrl/nodes v0.4.1 // indirect
	github.com/jmpsec/osctrl/queries v0.4.1 // indirect
	github.com/jmpsec/osctrl/types v0.4.1 // indirect
	github.com/jmpsec/osctrl/users v0.4.1
)

require (
	github.com/jmpsec/osctrl/utils v0.0.0-20241212115101-0bcbc42c27cb
	gorm.io/gorm v1.25.12
)

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/sys v0.28.0 // indirect
)

require (
	github.com/golang-jwt/jwt/v4 v4.5.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmpsec/osctrl/environments v0.0.0-20241212115101-0bcbc42c27cb // indirect
	github.com/jmpsec/osctrl/settings v0.4.1 // indirect
	github.com/jmpsec/osctrl/version v0.4.1 // indirect
	github.com/rs/zerolog v1.33.0
	github.com/segmentio/ksuid v1.0.4 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)
