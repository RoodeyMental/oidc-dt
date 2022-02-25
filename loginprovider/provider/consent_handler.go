package provider

import (
	"context"
	"fmt"
	"github.com/RoodeyMental/goidcdt/loginprovider/util"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/sirupsen/logrus"
	"html/template"
	"net/http"
	"path"
)

// ConsentHandler catch request from ORY Hydra with consent challenge.
func (s Service) ConsentHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	consentChallenge := r.URL.Query()["consent_challenge"][0]
	consentRequest := s.getConsentRequest(w, ctx, consentChallenge)
	consentPagePath := path.Join("views", "consent.html")
	consentTemplate, err := template.ParseFiles(consentPagePath)

	if err != nil {
		logrus.WithError(err).Errorln("Could not parse template")
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}

	requestedStandardScopes := s.getRequestedStandardScopes(consentRequest.Payload.RequestedScope)

	requestedStandardScopes = util.Remove(requestedStandardScopes, "openid")
	if err := consentTemplate.Execute(w, map[string]interface{}{
		"challenge":   consentChallenge,
		"scopes":      requestedStandardScopes,
		"application": consentRequest.Payload.Client.ClientID}); err != nil {
		logrus.WithError(err).Errorln("Could not execute template")
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
}

// ConsentResponseHandler reads consented scopes, extracts claims, retrieves and returns claim data from the database
func (s Service) ConsentResponseHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	err := r.ParseForm()
	if err != nil {
		logrus.WithError(err).Errorln("could not parse form")
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}

	consentChallenge := r.Form["consent_challenge"][0]
	consentRequest := s.getConsentRequest(w, ctx, consentChallenge)

	if consentRequest == nil {
		return
	}

	consentedStandardScopes := s.getConsentedStandardScopes(consentRequest.Payload.RequestedScope, r)
	if len(consentedStandardScopes) <= 0 {
		s.rejectConsentRequest(w, r, consentChallenge, ctx, "No scopes have been consented to", "User denied all requested scopes", "")
		return
	}

	previousConsentSession := s.getPreviousConsentSession(consentRequest.Payload.Subject)
	requestedCustomScopes := s.getRequestedCustomScopes(consentRequest.Payload.RequestedScope)

	//device scopes must be removed as they are not granted or denied by opa
	requestedRightsScopes := util.Remove(requestedCustomScopes, "device_auth", "device_trust")

	allowedRightsScopesDatabase := s.retainAllowedRightsScopesFromDatabase(requestedRightsScopes, consentRequest.Payload.Subject)

	if util.Contains(requestedCustomScopes, "device_trust") {
		hash, err := util.SHA1Hash(r.TLS.PeerCertificates[0].Raw)
		if err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
		}

		allowedScopesDeviceTrust := s.opa.GetAllowedScopesDeviceTrust(hash, consentRequest.Payload.Client.ClientID, append(consentedStandardScopes, allowedRightsScopesDatabase...))
		deniedScopes := util.Remove(util.Remove(consentRequest.Payload.RequestedScope, "device_auth", "device_trust"), allowedScopesDeviceTrust...)
		previousConsentSession = s.removeDeniedClaimsFromPreviousSession(deniedScopes, previousConsentSession)

		if len(allowedScopesDeviceTrust) <= 0 {
			s.rejectConsentRequest(w, r, consentChallenge, ctx, "insecure_device", "This happens when severe security issues are present", "Fix security issues and retry")
			return
		}

		if !util.Contains(allowedScopesDeviceTrust, "openid") {
			s.rejectConsentRequest(w, r, consentChallenge, ctx, "openid_denied", "Device Trust check denied openid scope, login denied", "Fix security issues and retry")
			return
		}

		allowedScopesDeviceTrust = append(allowedScopesDeviceTrust, "device_trust")

		claimsData := s.getClaimsData(allowedScopesDeviceTrust, consentedStandardScopes, consentRequest.Payload.Subject, consentRequest.Payload.Client.ClientID)
		if claimsData == nil {
			logrus.Info("No claim data read from database")
		}
		s.acceptConsentRequest(w, r, allowedScopesDeviceTrust, consentRequest, claimsData, consentChallenge, ctx, previousConsentSession)
		return
	}

	//remove denied scopes(no consent or user misses role in database)
	allowedScopes := append(consentedStandardScopes, allowedRightsScopesDatabase...)
	deniedScopes := util.Remove(util.Remove(consentRequest.Payload.RequestedScope, "device_auth", "device_trust"), allowedScopes...)
	previousConsentSession = s.removeDeniedClaimsFromPreviousSession(deniedScopes, previousConsentSession)

	//device_auth scope must be readded if it has been in requestedCustomScopes in order to be added to the id token
	if util.Contains(requestedCustomScopes, "device_auth") {
		allowedScopes = append(allowedScopes, "device_auth")
	}

	claimsData := s.getClaimsData(allowedScopes, consentedStandardScopes, consentRequest.Payload.Subject, consentRequest.Payload.Client.ClientID)
	s.acceptConsentRequest(w, r, allowedScopes, consentRequest, claimsData, consentChallenge, ctx, previousConsentSession)
}

//getConsentRequest reads ConsentRequest from ory hydra for a given consent challenge and returns it
func (s Service) getConsentRequest(w http.ResponseWriter, ctx context.Context, consentChallenge string) *admin.GetConsentRequestOK {
	resp, err := s.hydra.Admin.GetConsentRequest(
		&admin.GetConsentRequestParams{
			Context:          ctx,
			ConsentChallenge: consentChallenge,
		})
	if err != nil {
		logrus.WithError(err).Errorln("getConsentRequest error")
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return nil
	}

	return resp
}

//acceptConsentRequest accepts given consent requests and returns allowed scopes and claim data, redirects user agent
func (s Service) acceptConsentRequest(w http.ResponseWriter, r *http.Request, allowedScopes []string, resp *admin.GetConsentRequestOK, claimsData map[string]interface{}, consentChallenge string, ctx context.Context, previous *models.PreviousConsentSession) {
	if previous != nil {
		for k, v := range previous.Session.IDToken {
			switch elem := v.(type) {
			case map[string]interface{}:
				for scope := range elem {
					if scope == "device_trust" || scope == "device_auth" {
						claimsData[k].(map[string]string)[scope] = "established"
					} else {
						claimsData[k].(map[string]string)[scope] = "granted"
					}
				}
			default:
				claimsData[k] = v
			}
		}

		for _, value := range previous.GrantScope {
			if !util.Contains(allowedScopes, value) {
				allowedScopes = append(allowedScopes, value)
			}
		}
	}

	acceptResp, err := s.hydra.Admin.AcceptConsentRequest(
		&admin.AcceptConsentRequestParams{
			Body: &models.AcceptConsentRequest{
				GrantScope:               allowedScopes,
				GrantAccessTokenAudience: resp.Payload.RequestedAccessTokenAudience,
				Remember:                 true,
				RememberFor:              120,
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
		http.Error(w, "Internal Error", http.StatusInternalServerError)
	} else {
		logrus.WithField("url", acceptResp.Payload.RedirectTo).Infoln("ConsentHandler redirect")
		http.Redirect(w, r, acceptResp.Payload.RedirectTo, http.StatusFound)
	}
}

//rejectConsentRequest rejects consent request identified by given consent challenge and redirects user agent
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
		http.Error(w, "Internal Error", http.StatusInternalServerError)
	} else {
		logrus.WithField("url", rejectConsentRequest.Payload.RedirectTo).Infoln("ConsentHandler redirect")
		http.Redirect(w, r, rejectConsentRequest.Payload.RedirectTo, http.StatusFound)
	}
}

//getConsentedStandardScopes extracts consented standard scopes from html forms from a given request, returns slice of consented scopes
func (s Service) getConsentedStandardScopes(scopes []string, r *http.Request) []string {
	var consented []string

	for _, element := range scopes {
		scope := r.Form[element]
		if scope != nil && scope[0] == "on" {
			consented = append(consented, element)
		}
	}
	//openid scope must always be set
	consented = append(consented, "openid")

	return consented
}

//getClaimsData returns claim data corresponding to given consented scopes, returns nil in case of error
func (s Service) getClaimsData(allowedScopes []string, consentedStandardScopes []string, username string, clientID string) map[string]interface{} {
	var allowedCustomScopes []string

	//Create slice of claims from allowed scopes
	var claims []string
	for _, element := range allowedScopes {
		if element != "openid" {
			if util.Contains(consentedStandardScopes, element) {
				claims = append(claims, s.scopeMapping[element]...)
			} else {
				allowedCustomScopes = append(allowedCustomScopes, element)
			}
		}
	}

	var claimsData map[string]interface{}

	if len(claims) == 0 {
		if util.Contains(allowedScopes, "openid") {
			claimsData = make(map[string]interface{})
		} else {
			return nil
		}
	} else {
		claimsData = s.readClaimsFromDatabase(claims, username)
	}

	for _, element := range allowedCustomScopes {
		if claimsData[clientID] == nil {
			claimsData[clientID] = make(map[string]string)
		}
		if element == "device_auth" || element == "device_trust" {
			claimsData[clientID].(map[string]string)[element] = "established"
		} else {
			//clientID := s.getClientIDForRightsScope(element)
			claimsData[clientID].(map[string]string)[element] = "granted"
		}
	}

	return claimsData
}

//readClaimsFromDatabase extracts user data from the database corresponding to given claims
func (s Service) readClaimsFromDatabase(claims []string, username string) map[string]interface{} {
	//create comma separated list string of claims
	var columnsString string
	for index, claim := range claims {
		if index != len(claims)-1 {
			columnsString += claim + ","
		} else {
			columnsString += claim
		}
	}

	rows, err := s.db.Query("SELECT "+columnsString+" FROM users where username=?", username)

	if err != nil {
		logrus.WithError(err).Errorln("Cannot execute query to read claims from database")
		return nil
	}

	cols, _ := rows.Columns()

	rows.Next()
	columns := make([]interface{}, len(cols))
	columnPointers := make([]interface{}, len(cols))

	//create pointer for each column
	for i := range columns {
		columnPointers[i] = &columns[i]
	}

	//scan returned tuples into column pointers
	if err := rows.Scan(columnPointers...); err != nil {
		logrus.WithError(err).Errorln("Cannot scan query result into column pointer slice")
		return nil
	}

	//read data from columnPointers, cast it to strings, put string into map
	claimsData := make(map[string]interface{})
	for i, colName := range cols {
		val := columnPointers[i].(*interface{})
		switch v := (*val).(type) {
		case nil:
			claimsData[colName] = "null"
		case []uint8:
			claimsData[colName] = string(v)
		default:
			claimsData[colName] = fmt.Sprintf("%v", v)
		}
	}

	return claimsData
}

func (s Service) getRequestedStandardScopes(requestedScopes []string) []string {
	//extract requested standard scopes
	standardScopes := make([]string, len(s.scopeMapping))
	i := 0
	for k := range s.scopeMapping {
		standardScopes[i] = k
		i++
	}

	var requestedStandardScopes []string
	for _, requested := range requestedScopes {
		if util.Contains(standardScopes, requested) {
			requestedStandardScopes = append(requestedStandardScopes, requested)
		}
	}
	return requestedStandardScopes
}

func (s Service) getRequestedCustomScopes(requestedScopes []string) []string {
	return util.Difference(requestedScopes, s.getRequestedStandardScopes(requestedScopes))
}
