FROM ubuntu:18.04
LABEL maintainer="javuto"

RUN \
  apt update && apt install -y \
    build-essential \
    curl

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B \
  && add-apt-repository "deb [arch=amd64] https://pkg.osquery.io/deb deb main"

RUN apt-get update \
  && apt-get install -y osquery

RUN rm -rf /var/lib/apt/lists/*

CMD ["osqueryd", "--flagfile=/etc/osquery/osquery.flags", "--verbose"]
