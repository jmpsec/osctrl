module github.com/javuto/osctrl

go 1.12

require (
	github.com/beevik/etree v1.1.0 // indirect
	github.com/crewjam/saml v0.0.0-20190508002657-ca21de9dd5b9
	github.com/gorilla/mux v1.7.2
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/sessions v1.1.3
	github.com/javuto/osctrl/pkg/carves v0.1.2
	github.com/javuto/osctrl/pkg/environments v0.1.2
	github.com/javuto/osctrl/pkg/metrics v0.1.2
	github.com/javuto/osctrl/pkg/nodes v0.1.2
	github.com/javuto/osctrl/pkg/queries v0.1.2
	github.com/javuto/osctrl/pkg/settings v0.1.2
	github.com/javuto/osctrl/pkg/types v0.1.2
	github.com/javuto/osctrl/pkg/users v0.1.2
	github.com/javuto/osctrl/pkg/utils v0.1.2
	github.com/javuto/osctrl/plugins/db_logging v0.1.2 // indirect
	github.com/javuto/osctrl/plugins/graylog_logging v0.0.0-00010101000000-000000000000 // indirect
	github.com/javuto/osctrl/plugins/logging_dispatcher v0.1.2 // indirect
	github.com/javuto/osctrl/plugins/splunk_logging v0.1.2 // indirect
	github.com/jinzhu/gorm v1.9.10
	github.com/mattn/go-runewidth v0.0.4 // indirect
	github.com/olekukonko/tablewriter v0.0.1
	github.com/russellhaering/goxmldsig v0.0.0-20180430223755-7acd5e4a6ef7 // indirect
	github.com/segmentio/ksuid v1.0.2
	github.com/spf13/viper v1.4.0
	github.com/urfave/cli v1.20.0
)

replace github.com/javuto/osctrl/pkg/carves => ./pkg/carves

replace github.com/javuto/osctrl/pkg/settings => ./pkg/settings

replace github.com/javuto/osctrl/pkg/environments => ./pkg/environments

replace github.com/javuto/osctrl/pkg/metrics => ./pkg/metrics

replace github.com/javuto/osctrl/pkg/nodes => ./pkg/nodes

replace github.com/javuto/osctrl/pkg/queries => ./pkg/queries

replace github.com/javuto/osctrl/pkg/types => ./pkg/types

replace github.com/javuto/osctrl/pkg/users => ./pkg/users

replace github.com/javuto/osctrl/pkg/utils => ./pkg/utils

replace github.com/javuto/osctrl/plugins/logging_dispatcher => ./plugins/logging_dispatcher

replace github.com/javuto/osctrl/plugins/db_logging => ./plugins/db_logging

replace github.com/javuto/osctrl/plugins/splunk_logging => ./plugins/splunk_logging

replace github.com/javuto/osctrl/plugins/graylog_logging => ./plugins/graylog_logging
