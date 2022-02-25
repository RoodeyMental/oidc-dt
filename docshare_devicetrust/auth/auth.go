package auth

import (
	"context"
	"github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"net/http"
)

const (
	clientID     = "docshare_dt" //OAuth Client ID
	clientSecret = "secret"      //OAuth Client Secret, which is set at client registration
)

type Authenticator struct {
	Provider     *oidc.Provider
	ClientConfig oauth2.Config
	Ctx          context.Context
}

func NewAuthenticator() (*Authenticator, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, "http://localhost:4444/")
	if err != nil {
		logrus.WithError(err).Fatal("failed to get provider")
	}

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://127.0.0.1:5557/callback",
	}

	return &Authenticator{
		Provider:     provider,
		ClientConfig: config,
		Ctx:          ctx,
	}, nil
}

func RightIntToString(right int) string {
	if right == 0 {
		return "read"
	} else {
		return "write"
	}
}

func (auth Authenticator) RequestAuthentication(redirectUrl string, resp http.ResponseWriter, req *http.Request, accessScope string) {
	scopes := []string{"openid"}
	if accessScope == "internal" {
		scopes = append(scopes, "device_trust", "ds_internal_read", "ds_internal_write")
	} else if accessScope == "external" {
		scopes = append(scopes, "device_auth", "ds_external_read", "ds_external_write")
	} else {
		scopes = append(scopes, "ds_customer_read", "ds_customer_write")
	}

	auth.ClientConfig.RedirectURL = redirectUrl
	auth.ClientConfig.Scopes = scopes
	http.Redirect(resp, req, auth.ClientConfig.AuthCodeURL("statexyz"), http.StatusFound)
}
