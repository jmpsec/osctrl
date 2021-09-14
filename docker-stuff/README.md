# Osctrl Docker

## Generate OpenSSL public certificate and private key
1. `cp conf/tls/openssl.cnf.example conf/tls/openssl.cnf`
1. `vim conf/tls/openssl.cnf` and set:
    1. Set the location information under `[dn]`
    1. `C` – Set Country
    1. `ST` – Set state
    1. `L` – Set city
    1. `O` – Enter organization name
    1. `emailAddress` – Enter a valid e-mail for your org
1. Replace `example.com` in all fields with your domain
1. `openssl req -x509 -new -nodes -keyout conf/tls/tls.key -out conf/tls/tls.crt -config conf/tls/openssl.cnf`

## Generate JWT secret
1. `uuidgen | shasum -a 256 | awk '{print $1}'`
1. 

## References
### Osctrl
* [What is osctrl?](https://osctrl.net/)
* [osctrl-api](https://app.swaggerhub.com/apis-docs/jmpsec/osctrl-api/0.2.5#/)
* []()
* []()
* []()

### Docker
* [How to create new users in a Docker container?](https://net2.com/how-to-create-new-users-in-docker-container/)
* [Is mkdir -p totally safe when creating folder already exists](https://unix.stackexchange.com/questions/242995/is-mkdir-p-totally-safe-when-creating-folder-already-exists)
* [Meaning of ampersand (&) in docker-compose.yml file](https://stackoverflow.com/questions/45805380/meaning-of-ampersand-in-docker-compose-yml-file)
* [ChooseYourSIEMAdventure/docker-compose-splunk.yml](https://github.com/CptOfEvilMinions/ChooseYourSIEMAdventure/blob/main/docker-compose-splunk.yml)
* [Interactive shell using Docker Compose](https://stackoverflow.com/questions/36249744/interactive-shell-using-docker-compose)
* [Advanced Dockerfiles: Faster Builds and Smaller Images Using BuildKit and Multistage Builds](https://www.docker.com/blog/advanced-dockerfiles-faster-builds-and-smaller-images-using-buildkit-and-multistage-builds/)
* []()
* []()
* []()
* []()

### 
* []()
* []()
* []()
* []()
* []()
