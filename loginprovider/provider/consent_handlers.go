package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/sirupsen/logrus"
	"html/template"
	"io/ioutil"
	"net/http"
	"path"
)

// ConsentHandler catch request from ORY Hydra with consent challenge.
func (s Service) ConsentHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	consentChallenge := r.URL.Query()["consent_challenge"][0]

	resp := s.getConsentRequest(ctx, consentChallenge)

	fp := path.Join("views", "consent.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, map[string]interface{}{"challenge": consentChallenge, "scopes": resp.Payload.RequestedScope, "application": resp.Payload.Client.ClientID}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s Service) ConsentResponseHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	err := r.ParseForm()

	if err != nil {
		logrus.WithError(err).Errorln("could not parse form")
	}
	consentChallenge := r.Form["consent_challenge"][0]

	consentRequest := s.getConsentRequest(ctx, consentChallenge)

	consentedScopes := s.getConsentedScopes(consentRequest.Payload.RequestedScope, r)

	if consentedScopes == nil {
		s.rejectConsentRequest(w, r, consentChallenge, ctx, "No scopes have been consented to", "User denied all requested scopes", "")
	}

	allowedScopes := s.opa.GetAllowedScopes(r.TLS.PeerCertificates[0].Issuer.String(), r.TLS.PeerCertificates[0].SerialNumber.String(), consentedScopes)

	if allowedScopes == nil {
		s.rejectConsentRequest(w, r, consentChallenge, ctx, "Device Trust check denied all access", "This happens when severe security issues are present", "Fix security issues with your pc")
	}

	claimsData := s.getClaimsData(allowedScopes, consentRequest.Payload.Subject)

	s.acceptConsentRequest(w, r, err, allowedScopes, consentRequest, claimsData, consentChallenge, ctx)
}

func (s Service) getConsentRequest(ctx context.Context, consentChallenge string) *admin.GetConsentRequestOK {
	resp, err := s.hydra.Admin.GetConsentRequest(
		&admin.GetConsentRequestParams{
			Context:          ctx,
			ConsentChallenge: consentChallenge,
		})
	if err != nil {
		logrus.WithError(err).Errorln("getConsentRequest error")
	}
	return resp
}

func (s Service) acceptConsentRequest(w http.ResponseWriter, r *http.Request, err error, allowedScopes []string, resp *admin.GetConsentRequestOK, claimsData map[string]interface{}, consentChallenge string, ctx context.Context) {
	acceptResp, err := s.hydra.Admin.AcceptConsentRequest(
		&admin.AcceptConsentRequestParams{
			Body: &models.AcceptConsentRequest{
				GrantScope:               allowedScopes,
				GrantAccessTokenAudience: resp.Payload.RequestedAccessTokenAudience,
				Remember:                 true,
				RememberFor:              30,
				Session: &models.ConsentRequestSession{
					// Sets session data for the OpenID Connect ID token.
					IDToken: claimsData,
				},
			},
			ConsentChallenge: consentChallenge,
			Context:          ctx,
		})

	if err != nil {
		logrus.WithError(err).Errorln("AcceptConsentRequest error")
	}

	logrus.WithField("url", acceptResp.Payload.RedirectTo).Infoln("ConsentHandler redirect")
	http.Redirect(w, r, acceptResp.Payload.RedirectTo, http.StatusFound)
}

func (s Service) rejectConsentRequest(w http.ResponseWriter, r *http.Request, consentChallenge string, ctx context.Context, error string, errorDescription string, errorHint string) {
	rejectConsentRequest, err := s.hydra.Admin.RejectConsentRequest(&admin.RejectConsentRequestParams{
		Body: &models.RejectRequest{
			Error:            error,
			ErrorDescription: errorDescription,
			ErrorHint:        errorHint,
			StatusCode:       http.StatusForbidden,
		},
		ConsentChallenge: consentChallenge,
		Context:          ctx,
	})
	if err != nil {
		logrus.WithError(err).Errorln("rejectLoginRequest error")
	}

	logrus.WithField("url", rejectConsentRequest.Payload.RedirectTo).Infoln("ConsentHandler redirect")
	http.Redirect(w, r, rejectConsentRequest.Payload.RedirectTo, http.StatusFound)
}

func (s Service) getConsentedScopes(scopes []string, r *http.Request) []string {
	var consented []string

	for _, element := range scopes {
		scope := r.Form[element]
		if scope != nil && scope[0] == "on" {
			consented = append(consented, element)
		}
	}

	return consented
}

func (s Service) getClaimsData(consentedScopes []string, username string) map[string]interface{} {
	jsonRaw, err := ioutil.ReadFile(path.Join("conf", "scope-mapping.json"))
	if err != nil {
		logrus.WithError(err).Panic("Cannot read scope-mapping.json file")
	}

	var scopeMapping map[string][]string
	err = json.Unmarshal(jsonRaw, &scopeMapping)

	if err != nil {
		logrus.WithError(err).Panic("Cannot unmarshal scope-mapping.json file")
	}

	var claims []string
	for _, element := range consentedScopes {
		if element != "openid" {
			claims = append(claims, scopeMapping[element]...)
		}
	}

	return s.readClaimsFromDatabase(claims, username)
}

func (s Service) readClaimsFromDatabase(claims []string, username string) map[string]interface{} {
	var columnsString string
	for index, claim := range claims {
		if index != len(claims)-1 {
			columnsString += claim + ","
		} else {
			columnsString += claim
		}
	}

	rows, err := s.db.Query("SELECT "+columnsString+" FROM users where username=?", username) // Note: Ignoring errors for brevity

	if err != nil {
		logrus.WithError(err).Errorln("Cannot execute query to read claims from database")
	}

	cols, _ := rows.Columns()

	rows.Next()
	columns := make([]interface{}, len(cols))
	columnPointers := make([]interface{}, len(cols))
	for i := range columns {
		columnPointers[i] = &columns[i]
	}

	if err := rows.Scan(columnPointers...); err != nil {
		logrus.WithError(err).Errorln("Cannot scan query result into column pointer slice")
	}

	m := make(map[string]interface{})
	for i, colName := range cols {
		val := columnPointers[i].(*interface{})
		switch v := (*val).(type) {
		case nil:
			m[colName] = "null"
		case []uint8:
			m[colName] = string(v)
		default:
			m[colName] = fmt.Sprintf("%v", v)
		}
	}

	return m
}
