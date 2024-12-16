module github.com/jmpsec/osctrl/settings

go 1.23

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/queries => ../queries

replace github.com/jmpsec/osctrl/types => ../types

replace github.com/jmpsec/osctrl/utils => ../utils

require (
	github.com/jmpsec/osctrl/types v0.0.0-20241212115101-0bcbc42c27cb
	gorm.io/gorm v1.25.12
)

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/sys v0.28.0 // indirect
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmpsec/osctrl/nodes v0.0.0-20241212115101-0bcbc42c27cb // indirect
	github.com/jmpsec/osctrl/queries v0.0.0-20241212115101-0bcbc42c27cb // indirect
	github.com/jmpsec/osctrl/utils v0.0.0-20241212115101-0bcbc42c27cb // indirect
	github.com/rs/zerolog v1.33.0
	github.com/segmentio/ksuid v1.0.4 // indirect
	golang.org/x/text v0.21.0 // indirect
)
