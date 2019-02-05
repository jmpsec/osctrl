FROM golang
LABEL maintainer="javuto"

RUN go get github.com/crewjam/saml/samlsp
RUN go get github.com/gorilla/mux
RUN go get github.com/gorilla/securecookie
RUN go get github.com/gorilla/sessions
RUN go get github.com/jinzhu/gorm
RUN go get github.com/jinzhu/gorm/dialects/postgres
RUN go get github.com/spf13/viper
RUN go get github.com/unrolled/render
RUN go get github.com/urfave/cli

ADD tls.json /go/config
ADD deploy/data/3.3.0.json /go/data
ADD deploy/osquery-dev.conf /go/osquery-confs

ADD static /go/static
ADD templates/ /go/templates

RUN go build -o osctrl-tls .

EXPOSE 9000
EXPOSE 9001

CMD ["./osctrl-tls"]