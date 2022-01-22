# Running osctrl with Docker

You can use docker to run **osctrl** using the `docker-compose.yml` that ties all the components together.

There a couple of manual steps that are required before having a fully functional deployment:

1. Generate TLS/SSL termination certificate and private key
2. Generate JWT secret for API tokens

## Generate TLS/SSL termination certificate and private key

Follow these steps to generate a self-signed certificate that is going to be used for the osctrl deployment:

1. `cp conf/tls/openssl.cnf.example conf/tls/openssl.cnf`
2. `vim conf/tls/openssl.cnf` and set `emailAddress`  with valid e-mail for your org
3. Replace `osctrl.example.com` in all fields with your domain
4. `openssl req -x509 -new -nodes -keyout conf/tls/tls.key -out conf/tls/tls.crt -config conf/tls/openssl.cnf`

Alternatively, you can use [mkcert](https://github.com/FiloSottile/mkcert) to create a trusted local CA, for development and testing purposes.

For example once `mkcert` is installed, this will generate the TLS certificate and key for `osctrl.example.com`

```shell
mkcert -key-file "conf/tls/tls.key" -cert-file "conf/tls/tls.crt" "osctrl.example.com"
```

## Generate JWT secret

You can generate a random enough JWT secret to be used with the `osctrl-api` and `osctrl-admin` components using one of the following commands:

1. `uuidgen | shasum -a 256 | awk '{print $1}'`
2. `head -c64 < /dev/random | base64 | openssl dgst -sha256 | cut -d " " -f2`

It will be used to populate the `jwt.json` file.

## Using the `dockerize.sh` helper to automate the previous tasks

The helper `dockerize.sh` is provided to automate the steps outlined above

## References

Some links as reference for the topics in this README:

### osctrl

* [What is osctrl?](https://osctrl.net/)
* [osctrl-api](https://app.swaggerhub.com/apis-docs/jmpsec/osctrl-api/0.2.7#/)

### Docker

* [How to create new users in a Docker container?](https://net2.com/how-to-create-new-users-in-docker-container/)
* [Is mkdir -p totally safe when creating folder already exists](https://unix.stackexchange.com/questions/242995/is-mkdir-p-totally-safe-when-creating-folder-already-exists)
* [Meaning of ampersand (&) in docker-compose.yml file](https://stackoverflow.com/questions/45805380/meaning-of-ampersand-in-docker-compose-yml-file)
* [ChooseYourSIEMAdventure/docker-compose-splunk.yml](https://github.com/CptOfEvilMinions/ChooseYourSIEMAdventure/blob/main/docker-compose-splunk.yml)
* [Interactive shell using Docker Compose](https://stackoverflow.com/questions/36249744/interactive-shell-using-docker-compose)
* [Advanced Dockerfiles: Faster Builds and Smaller Images Using BuildKit and Multistage Builds](https://www.docker.com/blog/advanced-dockerfiles-faster-builds-and-smaller-images-using-buildkit-and-multistage-builds/)

### mkcert

* [mkcert is a simple tool for making locally-trusted development certificates](https://github.com/FiloSottile/mkcert)
