package main

import (
	"fmt"
	"crypto/x509"
	"io/ioutil"
	"crypto/tls"
	"github.com/mavricknz/ldap"
	log "github.com/sirupsen/logrus"
)

type AuthenticationProvider interface {
	Authenticate(username, password string) (r bool, e error)
}

type ldapAuthenticationProvider struct {
	conf *config
}

var tlsConfig *tls.Config

func newLdapAuthenticationProvider(conf *config) *ldapAuthenticationProvider {
	res := &ldapAuthenticationProvider{
		conf: conf,
	}
	res.setupTLS(conf.LdapHost)
	return res
}

func (auth *ldapAuthenticationProvider) setupTLS(servername string) {
	if conf.SslVerify {
		if conf.SslCaFile != "" {
			certs, err := loadCaFile(conf.SslCaFile)
			if err != nil {
				log.Fatal("Failed to setup LDAP TLS config:", err)
			}
			tlsConfig = &tls.Config{
				RootCAs:    certs,
				ServerName: servername,
			}
		}
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
}

func loadCaFile(file string) (*x509.CertPool, error) {
	roots := x509.NewCertPool()

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	roots.AppendCertsFromPEM(data)

	return roots, nil
}

func (auth *ldapAuthenticationProvider) Authenticate(username, password string) (r bool, e error) {
	// connect to ldap server
	l := ldap.NewLDAPSSLConnection(conf.LdapHost, uint16(conf.LdapPort), tlsConfig)
	e = l.Connect()
	if e != nil {
		log.WithFields(log.Fields{
			"error": e.Error(),
		}).Error("Failed to connect to LDAP server.")
		return
	}

	defer l.Close()

	// bind with authenticated user
	e = l.Bind(conf.BindUser, conf.BindPass)
	if e != nil {
		log.WithFields(log.Fields{
			"error": e.Error(),
		}).Error("Failed to bind to LDAP server.")
		return
	}

	// search user with filter
	ldapFilter := fmt.Sprintf(conf.LdapFilter, username)

	searchRequest := ldap.NewSimpleSearchRequest(
		conf.LdapBaseDN,
		2,
		ldapFilter,
		ldapAtrributes,
	)

	searchResult, err := l.Search(searchRequest)
	if err != nil {
		log.WithFields(log.Fields{
			"error":    err.Error(),
			"username": username,
		}).Warn("Failed to search LDAP server.")
		return
	}

	// bind with http user if it found on search
	if len(searchResult.Entries) == 1 {
		dn := searchResult.Entries[0].DN
		e = l.Bind(dn, password)
		if e == nil {
			r = true
		} else {
			log.WithFields(log.Fields{
				"error":    e.Error(),
				"username": username,
			}).Info("Authentication failed.")
		}
	} else {
		log.WithFields(log.Fields{
			"username": username,
		}).Info("User not found or not matching filter.")
	}

	return
}
