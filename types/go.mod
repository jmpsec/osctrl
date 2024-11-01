module github.com/jmpsec/osctrl/types

go 1.23

replace github.com/jmpsec/osctrl/nodes => ../nodes

replace github.com/jmpsec/osctrl/queries => ../queries

replace github.com/jmpsec/osctrl/utils => ../utils

require github.com/jmpsec/osctrl/queries v0.0.0-20241030113721-8e7065db6643

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmpsec/osctrl/nodes v0.0.0-20241030113721-8e7065db6643 // indirect
	github.com/jmpsec/osctrl/utils v0.0.0-20241101192351-fd857b3403fb // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/rs/zerolog v1.33.0 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	gorm.io/gorm v1.25.12 // indirect
)
