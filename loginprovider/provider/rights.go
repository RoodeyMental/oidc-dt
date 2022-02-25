package provider

import (
	"github.com/RoodeyMental/goidcdt/loginprovider/util"
	"github.com/sirupsen/logrus"
)

//readRightsScopesFromDatabase extracts rights scopes from database for a user
func (s Service) readRightsScopesFromDatabase(username string) []string {
	rows, err := s.db.Query("select roles_scopes.scope_fk from roles_scopes, user_role where user_role.username_fk=? and user_role.role_fk=roles_scopes.role_fk", username)

	if err != nil {
		logrus.WithError(err).Errorln("Cannot execute query to read rights scopes from database")
		return nil
	}

	var scopes []string

	if rows != nil {
		for rows.Next() {
			var resultScope string
			err := rows.Scan(&resultScope)
			if err != nil {
				logrus.Fatal(err)
			} else {
				scopes = append(scopes, resultScope)
			}
		}
		err = rows.Err()
		if err != nil {
			logrus.WithError(err).Errorln("error while evaluating sql result")
			return nil
		}
	}

	return scopes
}

func (s Service) retainAllowedRightsScopesFromDatabase(requestedRightsScopes []string, username string) []string {
	var retained []string

	allowed := s.readRightsScopesFromDatabase(username)

	for _, scope := range requestedRightsScopes {
		if util.Contains(allowed, scope) {
			retained = append(retained, scope)
		}
	}

	logrus.WithField("user", username).WithField("RequestedRightsScopes", requestedRightsScopes).Info("Requested rights scopes by user")
	logrus.WithField("user", username).WithField("AllowedRightsScopes", retained).Info("Allowed rights scopes by user")
	logrus.WithField("user", username).WithField("RetainedRightsScopes", retained).Info("Retained rights scopes by user")

	return retained
}

func (s Service) getClientIDForRightsScope(scope string) string {
	row := s.db.QueryRow("select rights_scopes.clientid_fk from rights_scopes where rights_scopes.scope=?", scope)

	var clientID string
	err := row.Scan(&clientID)

	if err != nil {
		logrus.WithError(err).WithField("scope", scope).Error("Error while reading clientid from database for scope")
	}

	return clientID
}
