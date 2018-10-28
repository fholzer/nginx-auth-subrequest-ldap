package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/mavricknz/ldap"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"gopkg.in/ini.v1"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	configPath = flag.String("c", "/etc/ldap/nginx_ldap_bind.ini", "Configuration file")

	basedn        string
	host          string
	port          uint64
	filter        string
	bindUser      string
	bindPass      string
	realm         string
	negTTL        time.Duration
	serverNetwork string
	serverAddress string

	sslVerify bool
	sslCaFile string

	errNoAuth       = errors.New("http: no or invalid authorization header")
	errHost         = errors.New("http: no credential for provided host")
	negotiate       = "Negotiate "
	basic           = "Basic "
	authorization   = "Authorization"
	wwwAuthenticate = "Www-Authenticate"

	ldapAtrributes = []string{"uid"}
)

func init() {
	flag.Parse()
	var err error
	if cfg, err = ini.Load(*configPath); err != nil {
		panic(err)
	}

	basedn = cfg.Section("").Key("ldap_basedn").String()
	host = cfg.Section("").Key("ldap_host").String()
	port, _ = cfg.Section("").Key("ldap_port").Uint64()
	filter = cfg.Section("").Key("ldap_filter").String()
	bindUser = cfg.Section("").Key("ldap_username").String()
	bindPass = cfg.Section("").Key("ldap_password").String()
	sslVerifyS := cfg.Section("").Key("ssl_verification").String()
	sslCaFile = cfg.Section("").Key("ssl_ca_file").String()
	serverNetwork = cfg.Section("").Key("server_network").String()
	serverAddress = cfg.Section("").Key("server_address").String()
	logFile := cfg.Section("").Key("log_file").String()
	logFormat := cfg.Section("").Key("log_format").String()
	logLevel := cfg.Section("").Key("log_level").String()
	realm = cfg.Section("").Key("httpauth_realm").String()
	ttl, _ := time.ParseDuration(cfg.Section("").Key("httpauth_cache_ttl").String())
	negTTL, _ = time.ParseDuration(cfg.Section("").Key("httpauth_cache_negative_ttl").String())
	cleanupInterval, _ := time.ParseDuration(cfg.Section("").Key("httpauth_cache_cleanup_intreval").String())
	c = cache.New(ttl, cleanupInterval)

	switch logFormat {
	case "text":
		log.SetFormatter(&log.TextFormatter{})
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	default:
		log.Fatal("Unknown log format.")
	}

	switch logFile {
	case "stdout":
		log.SetOutput(os.Stdout)
	case "stderr":
		log.SetOutput(os.Stderr)
	default:
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			log.SetOutput(file)
		} else {
			log.Fatal("Failed to open log file: ", err)
		}
	}

	lvl, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatal("Invalid log level.")
	}
	log.SetLevel(lvl)

	switch sslVerifyS {
	case "true":
		sslVerify = true
	case "false":
		sslVerify = false
	default:
		log.Fatal("Invalid value for ssl_verification option \"" + sslVerifyS + "\"")
	}
}

type authServer struct{}

type entry struct {
	response int
}

var c *cache.Cache
var tlsConfig *tls.Config //&tls.Config{InsecureSkipVerify: true}
var server = &authServer{}
var cfg *ini.File

func loadCaFile(file string) (*x509.CertPool, error) {
	roots := x509.NewCertPool()

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	roots.AppendCertsFromPEM(data)

	return roots, nil
}

func (s *authServer) authenticate(username, password string) (r bool, e error) {
	// connect to ldap server
	l := ldap.NewLDAPSSLConnection(host, uint16(port), tlsConfig)
	e = l.Connect()
	if e != nil {
		log.WithFields(log.Fields{
			"error": e.Error(),
		}).Error("Failed to connect to LDAP server.")
		return
	}

	defer l.Close()

	// bind with authenticated user
	e = l.Bind(bindUser, bindPass)
	if e != nil {
		log.WithFields(log.Fields{
			"error": e.Error(),
		}).Error("Failed to bind to LDAP server.")
		return
	}

	// search user with filter
	ldapFilter := fmt.Sprintf(filter, username)

	searchRequest := ldap.NewSimpleSearchRequest(
		basedn,
		2,
		ldapFilter,
		ldapAtrributes,
	)

	searchResult, err := l.Search(searchRequest)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to search LDAP server.")
		return
	}

	// bind with http user if it found on search
	if len(searchResult.Entries) == 1 {
		dn := searchResult.Entries[0].DN
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
		return "", nil, errNoAuth
	}

	data, err := base64.StdEncoding.DecodeString(h[i+1:])
	return h[:i+1], data, err
}

func (s *authServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add(wwwAuthenticate, fmt.Sprintf("Basic realm=\"%s\"", realm))

	headerValue := r.Header.Get(authorization)
	_, data, err := splitAuth(headerValue)
	if err != nil {
		w.WriteHeader(401)
		// TODO: should be Trace, as it may contain sensitive information
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"headerValue": headerValue,
			}).Debug("Malformed authorization header.")
		}
		return
	}

	i := bytes.IndexRune(data, ':')
	if i < 0 {
		w.WriteHeader(401)
		// TODO: should be Trace, as it may contain sensitive information
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"headerValue": headerValue,
			}).Debug("Malformed authorization header.")
		}
		return
	}
	username, password := string(data[:i]), string(data[i+1:])

	k := string(data)
	if x, found := c.Get(k); found {
		response := (x.(*entry)).response
		w.WriteHeader(response)
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"username": username,
				"response": response,
			}).Debug("Served response from cache.")
		}
		return
	}

	valid, _ := s.authenticate(username, password)
	if valid {
		c.Set(k, &entry{response: 200}, cache.DefaultExpiration)
		w.WriteHeader(200)
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"username": username,
				"response": 200,
			}).Debug("Successful authentication.")
		}
	} else {
		c.Set(k, &entry{response: 401}, negTTL)
		w.WriteHeader(401)
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"username": username,
				"response": 401,
			}).Debug("Failed authentication.")
		}
	}
}

func setupTLS() {
	if sslVerify {
		if sslCaFile != "" {
			certs, err := loadCaFile(sslCaFile)
			if err != nil {
				log.Fatal("Failed to setup LDAP TLS config:", err)
			}
			tlsConfig = &tls.Config{
				RootCAs: certs,
			}
		}
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
}

func main() {
	var (
		listener net.Listener
		err      error
	)

	// prepare graceful shutdown
	shuttingDown := false
	var gracefulStop = make(chan os.Signal)
	go func() {
		<-gracefulStop
		shuttingDown = true
		log.Info("Shutting down...")
		if listener != nil {
			listener.Close()
		}
	}()
	signal.Notify(gracefulStop, syscall.SIGTERM)
	signal.Notify(gracefulStop, syscall.SIGINT)

	setupTLS()

	// create listener if needed
	if serverNetwork != "stdin" {
		log.Info("Starting listener on  %s://%s", serverNetwork, serverAddress)
		listener, err = net.Listen(serverNetwork, serverAddress)
		if err != nil {
			log.Fatal("net.Listen:", err)
		}
	} else {
		log.Info("Using stdin as listener socket")
	}

	log.Info("Starting server...")
	if err = fcgi.Serve(listener, server); err != nil && shuttingDown == false {
		log.Fatal(err)
	}
}
