FROM centos:6
LABEL maintainer="javuto"

RUN curl -# "https://osquery-packages.s3.amazonaws.com/rpm/osquery-4.9.0-1.linux.$(arch).rpm" -o "/tmp/osquery.rpm"
RUN rpm -ivh "/tmp/osquery.rpm"

COPY deploy/docker/nodes/centos6/wait.sh .

CMD [ "/bin/sh", "wait.sh" ]
