package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/mavricknz/ldap"
	"github.com/patrickmn/go-cache"
	"gopkg.in/ini.v1"
	"log"
	"net/http"
	"net/http/fcgi"
	"strings"
	"time"
)

var (
	config_path = flag.String("c", "/etc/ldap/nginx_ldap_bind.ini", "Configuration file")

	basedn    string
	host      string
	port      uint64
	filter    string
	bind_user string
	bind_pass string
	realm     string

	ErrNoAuth       = errors.New("http: no or invalid authorization header")
	ErrHost         = errors.New("http: no credential for provided host")
	negotiate       = "Negotiate "
	basic           = "Basic "
	authorization   = "Authorization"
	wwwAuthenticate = "Www-Authenticate"

	ldap_atrributes = []string{"uid"}
)

func init() {
	flag.Parse()
	var err error
	if cfg, err = ini.Load(*config_path); err != nil {
		panic(err)
	}

	basedn = cfg.Section("").Key("ldap_basedn").String()
	host = cfg.Section("").Key("ldap_host").String()
	port, _ = cfg.Section("").Key("ldap_port").Uint64()
	filter = cfg.Section("").Key("ldap_filter").String()
	bind_user = cfg.Section("").Key("ldap_username").String()
	bind_pass = cfg.Section("").Key("ldap_password").String()
	realm = cfg.Section("").Key("httpauth_realm").String()
	ttl, _ := time.ParseDuration(cfg.Section("").Key("httpauth_cache_ttl").String())
	cleanupInterval, _ := time.ParseDuration(cfg.Section("").Key("httpauth_cache_cleanup_intreval").String())
	c = cache.New(ttl, cleanupInterval)
}

type Server struct{}

type entry struct {
	valid bool
}

var c *cache.Cache
var tlsConfig = &tls.Config{InsecureSkipVerify: true}
var server = &Server{}
var cfg *ini.File

func (s *Server) authenticate(username, password string) (r bool, e error) {
	// connect to ldap server
	l := ldap.NewLDAPSSLConnection(host, uint16(port), tlsConfig)
	e = l.Connect()
	if e != nil {
		return
	}

	defer l.Close()

	// bind with authenticated user
	e = l.Bind(bind_user, bind_pass)
	if e != nil {
		fmt.Println(e)
		return
	}

	// search user with filter
	ldap_filter := fmt.Sprintf(filter, username)

	search_request := ldap.NewSimpleSearchRequest(
		basedn,
		2,
		ldap_filter,
		ldap_atrributes,
	)

	search_result, err := l.Search(search_request)
	if err != nil {
		return
	}

	// bind with http user if it found on search
	if len(search_result.Entries) == 1 {
		dn := search_result.Entries[0].DN
		e = l.Bind(dn, password)
		if e == nil {
			r = true
		}
	}

	return
}

func splitAuth(h string) (string, []byte, error) {
	i := strings.Index(h, " ")
	if i < 0 {
		return "", nil, ErrNoAuth
	}

	data, err := base64.StdEncoding.DecodeString(h[i+1:])
	return h[:i+1], data, err
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add(wwwAuthenticate, fmt.Sprintf("Basic realm=\"%s\"", realm))

	_, data, err := splitAuth(r.Header.Get(authorization))
	if err != nil {
		w.WriteHeader(401)
		return
	}

	k := string(data)
	if _, found := c.Get(k); found {
		w.WriteHeader(200)
		return
	}

	i := bytes.IndexRune(data, ':')
	if i < 0 {
		w.WriteHeader(401)
		return
	}
	username, password := string(data[:i]), string(data[i+1:])
	valid, err := s.authenticate(username, password)
	if valid {
		c.Set(k, &entry{valid: true}, cache.DefaultExpiration)
		w.WriteHeader(200)
	} else {
		w.WriteHeader(401)
	}
}

func main() {
	log.Fatal(fcgi.Serve(nil, server))
}
