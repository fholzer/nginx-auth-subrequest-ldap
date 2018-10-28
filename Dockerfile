FROM golang:1.10-alpine
WORKDIR /go/src/github/fholzer/nginx-auth-subrequest-ldap
RUN apk --no-cache add ca-certificates git
RUN go get -u -v github.com/golang/dep/cmd/dep

COPY . /go/src/github/fholzer/nginx-auth-subrequest-ldap
RUN dep ensure
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -a .


FROM alpine:3.8
RUN apk --no-cache add ca-certificates
WORKDIR /usr/bin
COPY --from=0 /go/src/github/fholzer/nginx-auth-subrequest-ldap/nginx-auth-subrequest-ldap /usr/bin/nginx-auth-subrequest-ldap
COPY --from=0 /go/src/github/fholzer/nginx-auth-subrequest-ldap/example-config.ini /etc/ldap/nginx_ldap_bind.ini
VOLUME /var/run/nginx-auth-subrequest-ldap

CMD nginx-auth-subrequest-ldap
