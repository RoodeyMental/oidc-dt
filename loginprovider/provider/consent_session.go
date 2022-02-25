package provider

import (
	"context"
	"github.com/RoodeyMental/goidcdt/loginprovider/util"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/sirupsen/logrus"
	"time"
)

func (s Service) getPreviousConsentSession(subject string) *models.PreviousConsentSession {
	if sessions, err := s.hydra.Admin.ListSubjectConsentSessions(&admin.ListSubjectConsentSessionsParams{
		Subject: subject,
		Context: context.Background(),
	}); err == nil {
		return getMostRecentConsentSession(sessions.GetPayload())
	} else {
		return nil
	}
}

func getMostRecentConsentSession(payload []*models.PreviousConsentSession) *models.PreviousConsentSession {
	var mostRecent *models.PreviousConsentSession
	var mostRecentTime time.Time
	layout := "2006-01-02T15:04:05.000Z"
	var err error

	if len(payload) <= 0 {
		return nil
	}

	for _, session := range payload {
		var parsed time.Time
		dateTime := session.HandledAt.String()
		parsed, err = time.Parse(layout, dateTime)

		if mostRecent == nil {
			mostRecent = session
			mostRecentTime = parsed
			continue
		}

		if mostRecentTime.Before(parsed) {
			mostRecent = session
			mostRecentTime = parsed
		}
	}

	if err != nil {
		logrus.WithError(err).Println("Cannot parse 'handledAt' of previous consent session")
		return nil
	}

	return mostRecent
}

func (s Service) removeDeniedClaimsFromPreviousSession(scopes []string, session *models.PreviousConsentSession) *models.PreviousConsentSession {
	if session == nil {
		return nil
	}

	for _, scope := range scopes {
		//check if scope is standard scope
		if mapping := s.scopeMapping[scope]; mapping != nil {
			//if standard scope, remove claims if contained
			for _, claim := range mapping {
				delete(session.Session.IDToken, claim)
			}
			session.GrantScope = util.Remove(session.GrantScope, scope)
		} else {
			//if not standard scope, get clientid and check if contained in id token
			clientID := s.getClientIDForRightsScope(scope)
			if rightsScopes := session.Session.IDToken[clientID].(map[string]interface{}); rightsScopes != nil {
				delete(rightsScopes, scope)
				session.Session.IDToken[clientID] = rightsScopes
				session.GrantScope = util.Remove(session.GrantScope, scope)
			}
		}
	}
	return session
}
