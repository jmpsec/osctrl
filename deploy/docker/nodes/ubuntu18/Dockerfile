FROM ubuntu:18.04
LABEL maintainer="javuto"

RUN apt update && apt install -y curl

RUN curl -# "https://osquery-packages.s3.amazonaws.com/deb/osquery_4.0.2_1.linux.amd64.deb" -o "/tmp/osquery.deb"
RUN dpkg -i "/tmp/osquery.deb"

COPY deploy/docker/nodes/ubuntu18/wait.sh .

CMD [ "/bin/sh", "wait.sh" ]
