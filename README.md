# nginx-auth-subrequest-ldap

This service provides LDAP authentication for nginx via the [http_auth_request API](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html).

## Features

* Authentication cache with configurable TTL
  * Separate negative cache TTL configurable
* Separate search filters for authentication and authorization
* LDAP server certificate verification options:
  * disabled
  * enabled, using system default CA bundle
  * enabled, using custome CA bundle file
* Semantic logging, supporting:
  * text format
  * json format, ideal for shipping with Logstash or Filebeat

## Installation

### Build from source

`go get -u github.com/fholzer/nginx-auth-subrequest-ldap`

### Manually build binary

#### Mac OS X

`GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build`

#### Linux x86-32

`GOOS=linux GOARCH=386 CGO_ENABLED=0 go build`

#### Linux x86-64

`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build`

## Running

Use SystemD or [Supervisor](supervisord.org) to daemonize `nginx-auth-subrequest-ldap`

Check example configuration files and adapt to fit your needs
