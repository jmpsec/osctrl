FROM ubuntu:20.04
LABEL maintainer="javuto"

RUN apt update && apt install -y curl

RUN curl -# "https://osquery-packages.s3.amazonaws.com/deb/osquery_5.0.1-1.linux_$(dpkg --print-architecture).deb" -o "/tmp/osquery.deb"
RUN dpkg -i "/tmp/osquery.deb"

COPY deploy/docker/nodes/ubuntu20/wait.sh .

CMD [ "/bin/sh", "wait.sh" ]
