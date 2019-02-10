<div align="center">
  <img src="osctrl.png" />
</div>

</br>

## osctrl
Fast and efficient operative system management.

## Dependencies

*(Presuming that you aready have Golang > 1.8 installed in your system)*

The project uses [glide](https://glide.sh/) to manage dependencies. Make sure you have it installed, otherwise he easiest way to install the latest release on Mac or Linux is with the following script:

```shell
curl https://glide.sh/get | sh
```

On Mac OS X you can also install the latest release via [Homebrew](https://github.com/Homebrew/homebrew):

```shell
$ brew install glide
```

Once glide is ready, just run ``make deps`` and dependencies will be downloaded to ``vendor/`` directories for client and server.

If you want to update your dependencies, use ``make update`` and the latest version of each dependency will be downloaded.

Another option would be to see which dependency is needed and you can install in your ``$GOPATH``. The following commands should work:

```shell 
go get -u github.com/crewjam/saml/samlsp
go get -u github.com/gorilla/mux
go get -u github.com/gorilla/securecookie
go get -u github.com/gorilla/sessions
go get -u github.com/jinzhu/gorm
go get -u github.com/jinzhu/gorm/dialects/postgres
go get -u github.com/spf13/viper
go get -u github.com/unrolled/render
go get -u github.com/urfave/cli
```

## Service configuration

The most basic `tls.json` configuration file will have the following format:

```json
{
  "tls": {
    "listener": "127.0.0.1",
    "port": "_TLS_PORT",
    "host": "_TLS_HOST",
    "auth": "none",
    "debughttp": false
  },
  "db": {
    "host": "_DB_HOST",
    "port": "_DB_PORT",
    "name": "_DB_NAME",
    "username": "_DB_USERNAME",
    "password": "_DB_PASSWORD"
  },
  "logging": {
    "graylog": false,
    "graylogcfg": {
      "url": ""
    },
    "splunk": false,
    "splunkcfg": {
      "url": "", 
      "token": "",
      "search": "results_for_{{NAME}}"
    },
    "stdout": false,
    "postgres": true
  },
  "geolocation": {
    "map": false,
    "ipstackcfg": {
      "api": "",
      "apikey": ""
    },
    "googlemapscfg": {
      "api": "",
      "apikey": ""
    }
  }
}
```

And for `admin.json` it will look like this:

```json
{
  "admin": {
    "listener": "127.0.0.1",
    "port": "_ADMIN_PORT",
    "host": "_ADMIN_HOST",
    "auth": "local",
    "debughttp": false
  },
  "db": {
    "host": "_DB_HOST",
    "port": "_DB_PORT",
    "name": "_DB_NAME",
    "username": "_DB_USERNAME",
    "password": "_DB_PASSWORD"
  },
  "logging": {
    "graylog": false,
    "graylogcfg": {
      "url": ""
    },
    "splunk": false,
    "splunkcfg": {
      "url": "", 
      "token": "",
      "search": "results_for_{{NAME}}"
    },
    "stdout": false,
    "postgres": true
  },
  "geolocation": {
    "map": false,
    "ipstackcfg": {
      "api": "",
      "apikey": ""
    },
    "googlemapscfg": {
      "api": "",
      "apikey": ""
    }
  }
}
```

## Using docker

## Using vagrant

Running `vagrant up` creates a local virtual machine running Ubuntu 18.04 for local development. Once it has finished deploying, you can access it following the instructions in the terminal.
