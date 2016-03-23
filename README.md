# nginx-auth-adyax-ldap

This service provides LDAP authentication for nginx via the [http_auth_request API](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html).

## Features

* Authentication cache with configurable TTL
* Bind DN template integrates with any LDAP provider/schema
* Filter to search user on specified LDAP group

## Installation

`go get -u github.com/akuznecov/nginx-auth-subrequest-ldap`

## Manually build binary

### Mac OS X

`GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build`

### Linux 32 bit

`GOOS=linux GOARCH=386 CGO_ENABLED=0 go build`

### Linux 64 bit

`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build`

## Running

Use systemd or [supervisord](supervisord.org) to daemonize `nginx-auth-subrequest-ldap`
Check example configuration files and correct it for your own environment

