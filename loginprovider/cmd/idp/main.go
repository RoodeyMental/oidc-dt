package main

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/ory/hydra-client-go/client"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/RoodeyMental/goidcdt/loginprovider/provider"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

const (
	hydraAdmin           = "http://localhost:4445"
	caCertPath           = "./certs/ca-cert.pem"
	identityProviderCert = "./certs/identity-provider-cert.pem"
	identityProviderKey  = "./certs/identity-provider.key"
	databaseURL          = "root:123456@tcp(127.0.0.1:3306)/idp_accounts"
	databaseDriverType   = "mysql"
	identityProviderURL  = "identity-provider.local:8443"
	opaBaseURL           = "http://opa.local:8181/v1/data/"
)

func main() {
	adminURL, err := url.Parse(hydraAdmin)
	if err != nil {
		logrus.WithError(err).Fatalln("url parse error")
	}
	hydraClient := client.NewHTTPClientWithConfig(
		nil,
		&client.TransportConfig{
			Schemes:  []string{adminURL.Scheme},
			Host:     adminURL.Host,
			BasePath: adminURL.Path,
		},
	)
	opaClient := provider.NewOpaClient(opaBaseURL)

	db, err := sqlx.Open(databaseDriverType, databaseURL)
	if err != nil {
		logrus.WithError(err).Fatalln("unable to initialize database connection")
	}

	defer db.Close()

	srv := provider.NewService(hydraClient, db, opaClient)
	http.HandleFunc("/login", srv.LoginHandler)
	http.HandleFunc("/consent", srv.ConsentHandler)
	http.HandleFunc("/consentResponse", srv.ConsentResponseHandler)
	http.HandleFunc("/loginResponse", srv.LoginResponseHandler)
	http.HandleFunc("/signUp", srv.SignUpHandler)
	http.HandleFunc("/", srv.IndexHandler)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	caCert, err := ioutil.ReadFile(filepath.FromSlash(caCertPath))
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.VerifyClientCertIfGiven,
		MaxVersion: tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:      identityProviderURL,
		TLSConfig: tlsConfig,
	}

	log.Fatal(server.ListenAndServeTLS(filepath.FromSlash(identityProviderCert), filepath.FromSlash(identityProviderKey)))
}
