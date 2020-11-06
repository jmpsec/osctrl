FROM ubuntu:16.04
LABEL maintainer="javuto"

RUN apt update && apt install -y curl

RUN curl -# "https://osquery-packages.s3.amazonaws.com/deb/osquery_4.5.1_1.linux.amd64.deb" -o "/tmp/osquery.deb"
RUN dpkg -i "/tmp/osquery.deb"

COPY deploy/docker/nodes/ubuntu16/wait.sh .

CMD [ "/bin/sh", "wait.sh" ]
