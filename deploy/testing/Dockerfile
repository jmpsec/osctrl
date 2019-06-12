FROM ubuntu:latest
LABEL maintainer="javuto"

RUN apt-get update
RUN apt install curl -y --no-install-recommends

RUN curl -k "https://osquery-packages.s3.amazonaws.com/deb/osquery_3.3.2_1.linux.amd64.deb" -o "/tmp/osquery.deb"
RUN dpkg -i "/tmp/osquery.deb"
