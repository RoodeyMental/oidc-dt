package auth

import (
	"context"
	"github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"net/http"
)

const (
	clientID     = "docshare" //OAuth Client ID
	clientSecret = "secret"   //OAuth Client Secret, which is set at client registration
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

func (auth Authenticator) RequestAuthentication(redirectUrl string, resp http.ResponseWriter, req *http.Request) {
	auth.ClientConfig.RedirectURL = redirectUrl
	auth.ClientConfig.Scopes = []string{"openid"}
	http.Redirect(resp, req, auth.ClientConfig.AuthCodeURL("statexyz"), http.StatusFound)
}
