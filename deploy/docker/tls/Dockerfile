FROM golang:latest
LABEL maintainer="javuto"

ENV GO111MODULE=on

WORKDIR /osctrl-tls

#COPY /config/tls.json config/
#COPY /config/db.json config/

COPY . .

RUN go build -o bin/osctrl-tls tls/*.go
RUN go build -o bin/osctrl-cli cli/*.go

COPY deploy/docker/tls/wait.sh .

CMD [ "/bin/sh", "/osctrl-tls/wait.sh" ]
