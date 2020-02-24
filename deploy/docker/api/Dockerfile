FROM golang:latest
LABEL maintainer="javuto"

ENV GO111MODULE=on

WORKDIR /osctrl-api

#COPY /config/api.json config/
#COPY /config/db.json config/

COPY . .

RUN go build -o bin/osctrl-api api/*.go
RUN go build -o bin/osctrl-cli cli/*.go

ENTRYPOINT [ "/osctrl-api/bin/osctrl-api" ]
