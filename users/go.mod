module users

go 1.17

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/queries => ../queries

replace github.com/jmpsec/osctrl/types => ../types

require (
	github.com/golang-jwt/jwt/v4 v4.2.0
	github.com/jinzhu/gorm v1.9.16
	github.com/jmpsec/osctrl/types v0.0.0-20220120232002-31ecf3b9f264
	golang.org/x/crypto v0.0.0-20220112180741-5e0467b6c7ce
)

require (
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jmpsec/osctrl/nodes v0.0.0-20220120232002-31ecf3b9f264 // indirect
	github.com/jmpsec/osctrl/queries v0.3.1 // indirect
	github.com/lib/pq v1.10.4 // indirect
)
