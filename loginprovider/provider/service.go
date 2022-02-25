package provider

import (
	"encoding/json"
	"github.com/jmoiron/sqlx"
	"github.com/ory/hydra-client-go/client"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"path"
)

type Service struct {
	hydra        *client.OryHydra
	db           *sqlx.DB
	opa          *OpaClient
	scopeMapping map[string][]string
}

// NewService create new service instance.
func NewService(hydra *client.OryHydra, db *sqlx.DB, opaClient *OpaClient) *Service {
	jsonRaw, err := ioutil.ReadFile(path.Join("conf", "scope-mapping.json"))
	if err != nil {
		logrus.WithError(err).Panic("Cannot read scope-mapping.json file")
		return nil
	}

	//Unmarshal json scope->claims map
	var scopeMapping map[string][]string
	err = json.Unmarshal(jsonRaw, &scopeMapping)

	if err != nil {
		logrus.WithError(err).Panic("Cannot unmarshal scope-mapping.json file")
		return nil
	}
	return &Service{
		hydra:        hydra,
		db:           db,
		opa:          opaClient,
		scopeMapping: scopeMapping,
	}
}
