<p align="center">
  <img alt="osctrl" src="logo.png" />
  <p align="center">
    <a href="https://github.com/javuto/osctrl/blob/master/LICENSE.md"><img alt="Software License" src="https://img.shields.io/badge/license-GPL3-brightgreen.svg?style=flat-square"></a>
    <a href="https://travis-ci.org/javuto/osctrl"><img alt="Travis" src="https://img.shields.io/travis/javuto/osctrl/master.svg?style=flat-square"></a>
  </p>
</p>

## osctrl

Fast and efficient operative system management.

## Dependencies

*(Presuming that you aready have Golang >= 1.12 installed in your system)*

The project uses [Go modules](https://github.com/golang/go/wiki/Modules) to manage dependencies. Each package provides its own `go.mod` file and running `go build` will download all the required dependencies.

## Service configuration

The configuration for both the `tls` and the `admin` services needs to be provided. The `[admin-tls].json` file will have the following format:

```json
{
  "_SERVICE": {
    "listener": "127.0.0.1",
    "port": "_TLS_PORT",
    "host": "_TLS_HOST",
    "auth": "none",
    "logging": "db"
  }
}
```

The backend configuration file, `db.json`, will look like this:

```json
"db": {
  "host": "_DB_HOST",
  "port": "_DB_PORT",
  "name": "_DB_NAME",
  "username": "_DB_USERNAME",
  "password": "_DB_PASSWORD"
}
```

The `provision.sh` script will configure all necessary files for `osctrl` to function properly.

## Using docker

You can use docker to run `osctrl` and each service has a separate `Dockerfile` to run independently. Also there is a `docker-compose.yml` with the description of all services of a functional deployment.

Inside of the `docker` folder, execute the command `./dockerize.sh -u` to build and run all containers necessary for `osctrl`.

Ultimately you can just execute `make docker_all` and it will automagically build and run `osctrl` locally in docker.

## Using vagrant

Vagrant machines can be used for `osctrl` local development. Execute `vagrant up` to create a local virtual machine running Ubuntu 18.04. Once it has finished deploying, `osctrl` will be ready to be used and you can access it following the instructions in the terminal.

## Documentation

The documentation about `osctrl` is here.

## License

`osctrl` is released under the GPL 3 license.
