FROM golang:latest
LABEL maintainer="javuto"

ENV GO111MODULE=on

WORKDIR /osctrl-admin

#COPY /config/admin.json config/
#COPY /config/db.json config/

COPY cmd/admin/templates/ tmpl_admin
COPY cmd/admin/templates/components/page-head-online.html tmpl_admin/components/page-head.html
COPY cmd/admin/templates/components/page-js-online.html tmpl_admin/components/page-js.html
COPY cmd/admin/static/ static

COPY deploy/osquery/data/3.3.2.json data/
COPY deploy/osquery/osquery-dev.json data/

RUN mkdir -p carved_files

COPY go.mod .
COPY go.sum .

COPY cmd/admin/ cmd/admin
COPY cmd/cli/ cmd/cli
COPY pkg/ pkg
COPY plugins/ plugins

RUN go build -o bin/osctrl-admin cmd/admin/*.go
RUN go build -o bin/osctrl-cli cmd/cli/*.go

# Create dev environment
# RUN bin/osctrl-cli -D config/db.json environment add -n dev -host osctrl-tls -crt certs/osctrl.crt -conf data/osquery-dev.json

# Create admin user
# RUN bin/osctrl-cli -D config/db.json user add -u admin -p admin -a -n Admin

# ENTRYPOINT [ "bin/osctrl-admin" ]

COPY docker/admin/wait.sh .

CMD [ "/bin/sh", "/osctrl-admin/wait.sh" ]
