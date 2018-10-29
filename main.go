package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var (
	configPath = flag.String("c", "/etc/ldap/nginx_ldap_bind.ini", "Configuration file")
	conf       *config

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
	if conf, err = newConfigFromFile(configPath); err != nil {
		log.Fatal("Error reading config file:", err)
	}

	c = cache.New(conf.CacheTTL, conf.CacheCleanupInterval)

	switch conf.LogFormat {
	case "text":
		log.SetFormatter(&log.TextFormatter{})
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	default:
		log.Fatal("Unknown log format.")
	}

	switch conf.LogFile {
	case "stdout":
		log.SetOutput(os.Stdout)
	case "stderr":
		log.SetOutput(os.Stderr)
	default:
		file, err := os.OpenFile(conf.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			log.SetOutput(file)
		} else {
			log.Fatal("Failed to open log file: ", err)
		}
	}

	lvl, err := log.ParseLevel(conf.LogLevel)
	if err != nil {
		log.Fatal("Invalid log level.")
	}
	log.SetLevel(lvl)
}

type authServer struct {
	auth AuthenticationProvider
}

type entry struct {
	response int
}

var c *cache.Cache
var server = &authServer{}

func splitAuth(h string) (string, []byte, error) {
	i := strings.Index(h, " ")
	if i < 0 {
		return "", nil, errNoAuth
	}

	data, err := base64.StdEncoding.DecodeString(h[i+1:])
	return h[:i+1], data, err
}

func (s *authServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add(wwwAuthenticate, fmt.Sprintf("Basic realm=\"%s\"", conf.AuthRealm))

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

	valid, _ := s.auth.Authenticate(username, password)
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
		c.Set(k, &entry{response: 401}, conf.CacheNegativeTTL)
		w.WriteHeader(401)
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"username": username,
				"response": 401,
			}).Debug("Failed authentication.")
		}
	}
}

func main() {
	var (
		listener net.Listener
		err      error
	)

	server.auth = newLdapAuthenticationProvider(conf)

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

	// create listener if needed
	if conf.ServerNetwork != "stdin" {
		log.Infof("Starting listener on  %s://%s", conf.ServerNetwork, conf.ServerAddress)
		listener, err = net.Listen(conf.ServerNetwork, conf.ServerAddress)
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
