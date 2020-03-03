FROM golang:latest
LABEL maintainer="javuto"

ENV GO111MODULE=on

WORKDIR /osctrl-admin

#COPY /config/admin.json config/
#COPY /config/db.json config/

COPY . .

COPY admin/templates/ tmpl_admin
COPY admin/templates/components/page-head-online.html tmpl_admin/components/page-head.html
COPY admin/templates/components/page-js-online.html tmpl_admin/components/page-js.html
COPY admin/static/ static

COPY deploy/osquery/data/4.2.0.json data/
COPY deploy/osquery/osquery-dev.json data/

RUN mkdir -p carved_files

RUN go build -o bin/osctrl-admin admin/*.go
RUN go build -o bin/osctrl-cli cli/*.go

# Create dev environment
# RUN bin/osctrl-cli -D config/db.json environment add -n dev -host osctrl-tls -crt certs/osctrl.crt -conf data/osquery-dev.json

# Create admin user
# RUN bin/osctrl-cli -D config/db.json user add -u admin -p admin -a -n Admin

# ENTRYPOINT [ "bin/osctrl-admin" ]

COPY deploy/docker/admin/wait.sh .

CMD [ "/bin/sh", "/osctrl-admin/wait.sh" ]
