FROM golang:latest
LABEL maintainer="javuto"

ENV GO111MODULE=on

WORKDIR /osctrl-api

#COPY /config/api.json config/
#COPY /config/db.json config/

COPY go.mod .
COPY go.sum .

COPY cmd/api/ cmd/api
COPY cmd/cli/ cmd/cli
COPY pkg/ pkg

RUN go build -o bin/osctrl-api cmd/api/*.go
RUN go build -o bin/osctrl-cli cmd/cli/*.go

COPY docker/api/wait.sh .

CMD [ "/bin/sh", "/osctrl-api/wait.sh" ]
