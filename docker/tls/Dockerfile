FROM golang:latest
LABEL maintainer="javuto"

ENV GO111MODULE=on

WORKDIR /osctrl

#ADD /config/tls.json config/
#ADD /config/db.json config/

ADD cmd/tls/scripts/ scripts

COPY go.mod .
COPY go.sum .

COPY cmd/tls/ cmd/tls
COPY cmd/cli/ cmd/cli
COPY pkg/ pkg
COPY plugins/ plugins

RUN go build -buildmode=plugin -o plugins/logging_dispatcher_plugin.so plugins/logging_dispatcher/*.go
RUN go build -buildmode=plugin -o plugins/db_logging_plugin.so plugins/db_logging/*.go
RUN go build -buildmode=plugin -o plugins/graylog_logging_plugin.so plugins/graylog_logging/*.go
RUN go build -buildmode=plugin -o plugins/splunk_logging_plugin.so plugins/splunk_logging/*.go

RUN go build -o bin/osctrl-tls cmd/tls/*.go
RUN go build -o bin/osctrl-cli cmd/cli/*.go

EXPOSE 9000

ENTRYPOINT [ "bin/osctrl-tls" ]
