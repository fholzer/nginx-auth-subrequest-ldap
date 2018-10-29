package main

import (
	log "github.com/sirupsen/logrus"
	"gopkg.in/ini.v1"
	"time"
)

type config struct {
	LdapBaseDN               string
	LdapHost                 string
	LdapPort                 uint64
	LdapAuthenticationFilter string
	LdapAuthorizationFilter  string
	BindUser                 string
	BindPass                 string
	SslVerify                bool
	SslCaFile                string
	ServerNetwork            string
	ServerAddress            string
	LogFile                  string
	LogFormat                string
	LogLevel                 string
	AuthRealm                string
	CacheTTL                 time.Duration
	CacheNegativeTTL         time.Duration
	CacheCleanupInterval     time.Duration
}

func newConfigFromFile(filename *string) (*config, error) {
	var (
		cfg *ini.File
		err error
	)

	if cfg, err = ini.Load(*filename); err != nil {
		return nil, err
	}

	var res = &config{
		LdapBaseDN:               cfg.Section("").Key("ldap_basedn").String(),
		LdapHost:                 cfg.Section("").Key("ldap_host").String(),
		LdapAuthenticationFilter: cfg.Section("").Key("ldap_authentication_filter").String(),
		LdapAuthorizationFilter:  cfg.Section("").Key("ldap_authorization_filter").String(),
		BindUser:                 cfg.Section("").Key("ldap_username").String(),
		BindPass:                 cfg.Section("").Key("ldap_password").String(),
		SslCaFile:                cfg.Section("").Key("ssl_ca_file").String(),
		ServerNetwork:            cfg.Section("").Key("server_network").String(),
		ServerAddress:            cfg.Section("").Key("server_address").String(),
		LogFile:                  cfg.Section("").Key("log_file").String(),
		LogFormat:                cfg.Section("").Key("log_format").String(),
		LogLevel:                 cfg.Section("").Key("log_level").String(),
		AuthRealm:                cfg.Section("").Key("httpauth_realm").String(),
	}

	if res.SslVerify, err = cfg.Section("").Key("ssl_verification").Bool(); err != nil {
		log.Fatal("Invalid value for option ssl_verification")
	}

	if res.LdapPort, err = cfg.Section("").Key("ldap_port").Uint64(); err != nil {
		log.Fatal("Invalid value for option ldap_port")
	}

	res.CacheTTL = parseDuration(cfg, "httpauth_cache_ttl")
	res.CacheNegativeTTL = parseDuration(cfg, "httpauth_cache_negative_ttl")
	res.CacheCleanupInterval = parseDuration(cfg, "httpauth_cache_cleanup_interval")

	return res, nil
}

func parseDuration(cfg *ini.File, key string) time.Duration {
	val := cfg.Section("").Key(key).String()
	res, err := time.ParseDuration(val)
	if err != nil {
		log.Fatalf("Invalid value %s for option %s", val, key)
	}
	return res
}
