FROM golang:latest
LABEL maintainer="javuto"

ENV GO111MODULE=on

WORKDIR /osctrl-tls

#COPY /config/tls.json config/
#COPY /config/db.json config/

COPY . .

COPY tls/scripts/ scripts

RUN go build -o bin/osctrl-tls tls/*.go
RUN go build -o bin/osctrl-cli cli/*.go

ENTRYPOINT [ "/osctrl-tls/bin/osctrl-tls" ]
