package provider

import (
	"context"
	"github.com/RoodeyMental/goidcdt/loginprovider/util"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
	"path"

	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/sirupsen/logrus"
)

// LoginHandler catch request from ORY Hydra with login challenge.
func (s Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	loginChallenge := r.URL.Query()["login_challenge"][0]

	// get login request from Hydra admin API.
	loginRequest := s.getLoginRequest(w, ctx, loginChallenge)

	if loginRequest == nil {
		return
	}

	requestedStandardScopes := s.getRequestedStandardScopes(loginRequest.Payload.RequestedScope)
	if !util.Contains(requestedStandardScopes, "openid") {
		logrus.Errorln("Scope 'openid' not present. Authentication-Request MUST contain 'openid' scope value! Aborting request...")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	//if device_auth and device_trust scope present
	if util.Contains(loginRequest.Payload.RequestedScope, "device_auth") && util.Contains(loginRequest.Payload.RequestedScope, "device_trust") {
		http.Error(w, "Scopes 'device_trust' and 'device_auth' cannot be combined", http.StatusBadRequest)
		return
	}

	if util.Contains(loginRequest.Payload.RequestedScope, "device_auth") ||
		(util.Contains(loginRequest.Payload.RequestedScope, "device_trust")) {
		if len(r.TLS.PeerCertificates) <= 0 {
			s.rejectLoginRequest(w, r, loginChallenge, "no_device", "Device authentication requested but no certificate provided")
			return
		}

		if cert, err := util.SHA1Hash(r.TLS.PeerCertificates[0].Raw); err == nil {
			if !s.checkCertificate(cert) {
				s.rejectLoginRequest(w, r, loginChallenge, "unregistered_device", "Device not registered")
				return
			}
		} else {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
	}

	// if client already authorized
	if loginRequest.Payload.Skip {
		logrus.Info("Detecting previous login, accepting login request...")
		s.acceptLoginRequest(w, r, loginRequest.Payload.Subject, loginChallenge)
	}

	fp := path.Join("views", "login.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, map[string]interface{}{"challenge": loginChallenge}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//logrus.Debugln("Client Certificate attempting login - Serial Number: " + r.TLS.PeerCertificates[0].SerialNumber.String())
	//logrus.Debug("Issuer: " + r.TLS.PeerCertificates[0].Issuer.CommonName)
}

// LoginResponseHandler checks the username and password of the user and draws conclusions.
func (s Service) LoginResponseHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	err := r.ParseForm()

	if err != nil {
		logrus.WithError(err).Errorln("could not parse form")
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
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

	loginRequest := s.getLoginRequest(w, ctx, loginChallenge)

	if util.Contains(loginRequest.Payload.RequestedScope, "device_auth") || util.Contains(loginRequest.Payload.RequestedScope, "device_trust") {
		if !s.checkCertificateByUser(r.TLS.PeerCertificates[0].Raw, login) {
			s.rejectLoginRequest(w, r, loginChallenge, "device_not_allowed", "Device is not linked to user")
			return
		}
	}

	if !s.checkPassword(login, password) {
		s.rejectLoginRequest(w, r, loginChallenge, "password_incorrect", "Username and password do not match")
	} else {
		s.acceptLoginRequest(w, r, login, loginChallenge)
	}
}

//getLoginRequest reads login request corresponding to the given loginChallenge from ory hydra
func (s Service) getLoginRequest(w http.ResponseWriter, ctx context.Context, loginChallenge string) *admin.GetLoginRequestOK {
	loginResp, err := s.hydra.Admin.GetLoginRequest(
		&admin.GetLoginRequestParams{
			Context:        ctx,
			LoginChallenge: loginChallenge,
		})
	if err != nil {
		logrus.WithError(err).Errorln("getLoginRequest error")
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return nil
	}
	return loginResp
}

//acceptLoginRequest accepts login request corresponding to the given loginChallenge
func (s Service) acceptLoginRequest(w http.ResponseWriter, r *http.Request, login string, loginChallenge string) {
	acceptResp, err := s.hydra.Admin.AcceptLoginRequest(&admin.AcceptLoginRequestParams{
		Body: &models.AcceptLoginRequest{
			Subject:     &login,
			Remember:    true,
			RememberFor: 120, // 30 seconds.
		},
		LoginChallenge: loginChallenge,
		Context:        context.Background(),
	})
	if err != nil {
		logrus.WithError(err).Errorln("acceptLoginRequest error")
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
	logrus.WithField("url", acceptResp.Payload.RedirectTo).Infoln("LoginResponseHandler redirect")
	http.Redirect(w, r, acceptResp.Payload.RedirectTo, http.StatusFound)
}

func (s Service) rejectLoginRequest(w http.ResponseWriter, r *http.Request, loginChallenge string, error string, errorDescription string) {
	rejectResponse, err := s.hydra.Admin.RejectLoginRequest(&admin.RejectLoginRequestParams{
		Body: &models.RejectRequest{
			Error:            error,
			StatusCode:       http.StatusForbidden,
			ErrorDescription: errorDescription,
		},
		LoginChallenge: loginChallenge,
		Context:        context.Background(),
	})
	if err != nil {
		logrus.WithError(err).Errorln("rejectLoginRequest error")
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}

	logrus.WithField("url", rejectResponse.Payload.RedirectTo).Infoln("LoginResponseHandler redirect")
	http.Redirect(w, r, rejectResponse.Payload.RedirectTo, http.StatusFound)
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
