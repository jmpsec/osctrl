FROM golang:latest
LABEL maintainer="javuto"

ENV GO111MODULE=on

WORKDIR /osctrl

#ADD /config/admin.json config/
#ADD /config/db.json config/

ADD cmd/admin/templates/ tmpl_admin
ADD cmd/admin/templates/components/page-head-online.html tmpl_admin/components/page-head.html
ADD cmd/admin/templates/components/page-js-online.html tmpl_admin/components/page-js.html
ADD cmd/admin/static/ static

ADD deploy/osquery/data/3.3.2.json data/
ADD deploy/osquery/osquery-empty.json data/

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
# RUN bin/osctrl-cli -D config/db.json environment add -n dev -host localhost -crt certs/osctrl.crt -conf config/osquery-dev.json

# Create admin user
# RUN bin/osctrl-cli -D config/db.json user add -u admin -p admin -a -n Admin

# ENTRYPOINT [ "bin/osctrl-admin" ]

COPY docker/admin/wait.sh .

CMD [ "/bin/sh", "/osctrl/wait.sh" ]
