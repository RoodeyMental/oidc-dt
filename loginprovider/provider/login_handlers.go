package provider

import (
	"context"
	"crypto/x509"
	"database/sql"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
	"path"

	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/sirupsen/logrus"
)

type device struct {
	issuer string
	serial string
}

// LoginHandler catch request from ORY Hydra with login challenge.
func (s Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	loginChallenge := r.URL.Query()["login_challenge"][0]

	// get login request from Hydra admin API.
	loginResp := s.getLoginRequest(ctx, loginChallenge)

	// if client already authorized
	if loginResp.Payload.Skip {
		s.acceptLoginRequest(w, r, loginResp.Payload.Subject, loginChallenge)
	}

	fp := path.Join("views", "login.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, map[string]interface{}{"challenge": loginChallenge}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	logrus.Debugln("Client Certificate attempting login - Serial Number: " + r.TLS.PeerCertificates[0].SerialNumber.String())
	logrus.Debugln("Issuer: " + r.TLS.PeerCertificates[0].Issuer.CommonName)
}

// LoginResponseHandler checks the username and password of the user and draws conclusions.
func (s Service) LoginResponseHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()

	if err != nil {
		logrus.WithError(err).Errorln("could not parse form")
	}

	login := r.Form["login"][0]
	password := r.Form["password"][0]
	loginChallenge := r.Form["loginChallenge"][0]

	logrus.
		WithFields(
			logrus.Fields{
				"login":          login,
				"password":       password,
				"loginChallenge": loginChallenge,
			}).
		Infoln("LogIn request")

	if !s.checkPassword(login, password) {
		s.rejectLoginRequest(w, r, loginChallenge, "Password incorrect")
	} else if !s.checkCertificate(r.TLS.PeerCertificates[0], login) {
		s.rejectLoginRequest(w, r, loginChallenge, "Bad Device Certificate")
	} else {
		s.acceptLoginRequest(w, r, login, loginChallenge)
	}
}

func (s Service) getLoginRequest(ctx context.Context, loginChallenge string) *admin.GetLoginRequestOK {
	loginResp, err := s.hydra.Admin.GetLoginRequest(
		&admin.GetLoginRequestParams{
			Context:        ctx,
			LoginChallenge: loginChallenge,
		})
	if err != nil {
		logrus.WithError(err).Errorln("getLoginRequest error")
	}
	return loginResp
}

func (s Service) acceptLoginRequest(w http.ResponseWriter, r *http.Request, login string, loginChallenge string) {
	acceptResp, err := s.hydra.Admin.AcceptLoginRequest(&admin.AcceptLoginRequestParams{
		Body: &models.AcceptLoginRequest{
			Subject:     &login,
			Remember:    true,
			RememberFor: 30, // 30 seconds.
		},
		LoginChallenge: loginChallenge,
		Context:        context.Background(),
	})
	if err != nil {
		logrus.WithError(err).Errorln("acceptLoginRequest error")
	}
	logrus.WithField("url", acceptResp.Payload.RedirectTo).Infoln("LoginResponseHandler redirect")
	http.Redirect(w, r, acceptResp.Payload.RedirectTo, http.StatusFound)
}

func (s Service) rejectLoginRequest(w http.ResponseWriter, r *http.Request, loginChallenge string, error string) {
	rejectResponse, err := s.hydra.Admin.RejectLoginRequest(&admin.RejectLoginRequestParams{
		Body: &models.RejectRequest{
			Error:      error,
			StatusCode: http.StatusForbidden,
		},
		LoginChallenge: loginChallenge,
		Context:        context.Background(),
	})
	if err != nil {
		logrus.WithError(err).Errorln("rejectLoginRequest error")
	}

	logrus.WithField("url", rejectResponse.Payload.RedirectTo).Infoln("LoginResponseHandler redirect")
	http.Redirect(w, r, rejectResponse.Payload.RedirectTo, http.StatusFound)
}

func (s Service) rowExists(query string, args ...interface{}) bool {
	var exists bool
	query = fmt.Sprintf("SELECT exists (%s)", query)
	err := s.db.QueryRow(query, args...).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		logrus.WithError(err).Errorln("error checking if row exists '%s'", args)
	}
	return exists
}

func (s Service) checkCertificate(certificate *x509.Certificate, username string) bool {
	queryGetDevices := "SELECT serial,issuer FROM devices WHERE username=?"
	rows, err := s.db.Query(queryGetDevices, username)
	var devices []device

	if rows != nil {
		for rows.Next() {
			var resultIssuer string
			var resultSerial string
			err := rows.Scan(&resultSerial, &resultIssuer)
			if err != nil {
				logrus.Fatal(err)
			} else {
				devices = append(devices, device{
					issuer: resultIssuer,
					serial: resultSerial,
				})
			}
		}
		err = rows.Err()
		if err != nil {
			logrus.WithError(err).Errorln("error while evaluating sql result")
		}
	}
	containsDevice := false
	for _, device := range devices {
		if certificate.Issuer.String() == device.issuer && certificate.SerialNumber.String() == device.serial {
			containsDevice = true
			break
		}
	}
	return containsDevice
}

func (s Service) checkPassword(login string, password string) bool {
	queryGetUser := "SELECT password FROM users WHERE username=?"
	rows := s.db.QueryRow(queryGetUser, login)
	var resultPassword []byte

	if err := rows.Scan(&resultPassword); err != nil {
		logrus.WithError(err).Errorln("could not retrieve password from db")
		return false
	}
	return bcrypt.CompareHashAndPassword(resultPassword, []byte(password)) == nil
}
