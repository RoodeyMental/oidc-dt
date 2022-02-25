package provider

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

type OpaClient struct {
	url    string
	client *http.Client
}

type OpaRequest struct {
	Input Input `json:"input"`
}

type Input struct {
	CertificateHash string `json:"certificate"`
}
type OpaResponse struct {
	Result map[string]bool `json:"result"`
}

func NewOpaClient(url string) *OpaClient {
	return &OpaClient{
		url:    url,
		client: &http.Client{},
	}
}

func (opa OpaClient) GetAllowedScopesDeviceTrust(cert []byte, clientID string, requestedScopes []string) []string {
	certEncoded := hex.EncodeToString(cert)
	certRequest, err := json.Marshal(OpaRequest{
		Input: Input{
			CertificateHash: certEncoded,
		},
	})

	if err != nil {
		logrus.WithError(err).Errorln("Cannot marshal opa request")
		return nil
	}

	req, err := http.NewRequest("POST", opa.url+clientID, bytes.NewBuffer(certRequest))

	if err != nil {
		logrus.WithError(err).Errorln("Cannot create new http request")
		return nil
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := opa.client.Do(req)

	if err != nil {
		logrus.WithError(err).Errorln("Cannot execute http request")
		return nil
	}

	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		logrus.WithError(err).Errorln("Cannot read http response body")
		return nil
	}

	var opaResp OpaResponse
	if err = json.Unmarshal(bodyBytes, &opaResp); err != nil {
		logrus.WithError(err).Errorln("Cannot unmarshal opa response body")
		return nil
	}

	var allowedScopes []string

	for _, scope := range requestedScopes {
		if opaResp.Result[scope] {
			allowedScopes = append(allowedScopes, scope)
		}
	}

	return allowedScopes
}
