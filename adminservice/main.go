package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"

	"github.com/RoodeyMental/goidcdt/adminservice/handlers"
	_ "github.com/go-sql-driver/mysql"
)

const (
	caCertPath         = "./certs/ca-cert.pem"
	adminServiceCert   = "./certs/admin-service-cert.pem"
	adminServiceKey    = "./certs/admin-service.key"
	adminServiceURL    = "admin-service.local:8444"
	databaseDriverType = "mysql"
	databaseURL        = "root:123456@tcp(127.0.0.1:3306)/idp_accounts"
)

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func main() {
	db, err := sql.Open(databaseDriverType, databaseURL)
	defer db.Close()

	if err != nil {
		logrus.WithError(err).Fatalln("unable to initialize database connection")
	}

	cookieStore := sessions.NewCookieStore([]byte("securetestkey")) //TODO: store key in an environment variable, for production code
	srv := provider.NewService(db, cookieStore)

	http.HandleFunc("/adminLoginRequest", srv.AdminLoginRequestHandler)
	http.HandleFunc("/adminLogin", srv.AdminLoginHandler)
	http.HandleFunc("/addClientCert", srv.AddClientCertificateHandler)
	http.HandleFunc("/addClientCertRequest", srv.AddClientCertificateRequestHandler)

	caCert, err := ioutil.ReadFile(filepath.FromSlash(caCertPath))
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.NoClientCert,
	}

	server := &http.Server{
		Addr:      adminServiceURL,
		TLSConfig: tlsConfig,
	}

	logrus.Fatal(server.ListenAndServeTLS(filepath.FromSlash(adminServiceCert), filepath.FromSlash(adminServiceKey)))
}
