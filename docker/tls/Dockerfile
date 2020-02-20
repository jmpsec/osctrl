FROM golang:latest
LABEL maintainer="javuto"

ENV GO111MODULE=on

WORKDIR /osctrl-tls

#COPY /config/tls.json config/
#COPY /config/db.json config/

COPY cmd/tls/scripts/ scripts

COPY go.mod .
COPY go.sum .

COPY cmd/tls/ cmd/tls
COPY cmd/cli/ cmd/cli
COPY pkg/ pkg

RUN go build -o bin/osctrl-tls cmd/tls/*.go
RUN go build -o bin/osctrl-cli cmd/cli/*.go

COPY docker/tls/wait.sh .

CMD [ "/bin/sh", "/osctrl-tls/wait.sh" ]
