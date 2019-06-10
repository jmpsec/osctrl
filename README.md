<div align="center">
  <img src="logo.png" />
</div>

</br>

## osctrl

Fast and efficient operative system management.

## Dependencies

*(Presuming that you aready have Golang >= 1.12 installed in your system)*

The project uses [Go modules](https://github.com/golang/go/wiki/Modules) to manage dependencies. Each package provides its own `go.mod` file and running `go build` will download all the required dependencies.

## Service configuration

The most basic `tls.json` configuration file will have the following format:

```json
{
  "tls": {
    "listener": "127.0.0.1",
    "port": "_TLS_PORT",
    "host": "_TLS_HOST",
    "auth": "none",
    "logging": "stdout"
  },
  "db": {
    "host": "_DB_HOST",
    "port": "_DB_PORT",
    "name": "_DB_NAME",
    "username": "_DB_USERNAME",
    "password": "_DB_PASSWORD"
  }
}
```

And for `admin.json` it will look very similar:

```json
{
  "admin": {
    "listener": "127.0.0.1",
    "port": "_ADMIN_PORT",
    "host": "_ADMIN_HOST",
    "auth": "local",
    "logging": "stdout"
  },
  "db": {
    "host": "_DB_HOST",
    "port": "_DB_PORT",
    "name": "_DB_NAME",
    "username": "_DB_USERNAME",
    "password": "_DB_PASSWORD"
  }
}
```

## Using docker

You can use docker to run  `osctrl` and each service has a separate `Dockerfile` to run independently. Also there is a `docker-compose.yml` with the description of all services of a functional deployment.

Use the files `Dockerfile-[tls,admin,nginx]` to bring up each service, after being built. For example to build the container use:

```shell
docker -t osctrl-tls -f Dockerfile-tls .
```

And after the build is successful, you can run the container as follows:

```shell
docker run osctrl-tls
```

Likewise you can build and bring up all services at once, using `docker-compose build` and `docker-compose up`.

Ultimately you can just execute `make docker_all` and it will automagically build and run osctrl locally in docker.

## Using vagrant

Vagrant machines can be used for `osctrl` local development. Execute `vagrant up ubuntu` or `vagrant up centos` to create a local virtual machine running Ubuntu 18.04 or CentOS 7 respectively. Once it has finished deploying, `osctrl` will be ready to be used and you can access it following the instructions in the terminal.
