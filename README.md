# osctrl

<p align="center">
  <img alt="osctrl" src="logo.png" width="300" />
  <p align="center">
    Fast and efficient osquery management.
  </p>
  <p align="center">
    <a href="https://github.com/jmpsec/osctrl/blob/master/LICENSE.md">
      <img alt="Software License" src="https://img.shields.io/badge/license-GPL3-brightgreen.svg?style=flat-square">
    </a>
    <a href="https://travis-ci.org/jmpsec/osctrl">
      <img alt="Travis" src="https://img.shields.io/travis/jmpsec/osctrl/master.svg?style=flat-square">
    </a>
    <a href="https://goreportcard.com/report/github.com/jmpsec/osctrl">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/jmpsec/osctrl?style=flat-square&fuckgithubcache=1">
    </a>
  </p>
</p>

## What is osctrl?

**osctrl** is a fast and efficient [osquery](https://osquery.io) management solution, implementing its [remote API](https://osquery.readthedocs.io/en/stable/deployment/remote/) as TLS endpoint.

With **osctrl** you can monitor all your systems running osquery, distribute its configuration fast, collect all the status and result logs and allow you to run on-demand queries.

## Running osctrl with docker

You can use docker to run **osctrl** and each component has a separate `Dockerfile` to run independently. Also there is a `docker-compose.yml` that ties all the components together, to serve a functional deployment.

Inside of the `docker` folder, execute the command `./dockerize.sh -u` to build and run all containers necessary for **osctrl**.

Ultimately you can just execute `make docker_all` and it will automagically build and run **osctrl** locally in docker.

## Running osctrl with vagrant

Vagrant machines can be used for **osctrl** local development. Execute `vagrant up` to create a local virtual machine running Ubuntu 18.04. Once it has finished deploying, **osctrl** will be ready to be used and you can access it following the instructions in the terminal.

## Documentation

You can find the documentation of the project in [https://osctrl.net](https://osctrl.net)

## License

This project is released under the GPL 3 license.
