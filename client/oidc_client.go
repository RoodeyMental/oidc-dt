package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"net/http"

	oidc "github.com/coreos/go-oidc"
)

const (
	clientID     = "auth-code-client3" //OAuth Client ID
	clientSecret = "secret"            //OAuth Client Secret, which is set at client registration
)

type Authenticator struct {
	provider     *oidc.Provider
	clientConfig oauth2.Config
	ctx          context.Context
}

func newAuthenticator() (*Authenticator, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, "http://localhost:4444/")
	if err != nil {
		logrus.WithError(err).Fatal("failed to get provider")
	}

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:5555/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "address"},
	}

	return &Authenticator{
		provider:     provider,
		clientConfig: config,
		ctx:          ctx,
	}, nil
}

func (a *Authenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	logrus.WithField("host", r.Host).Debugln("New Callback from")
	if r.URL.Query().Get("state") != "statexyz" {
		http.Error(w, "statexyz did not match", http.StatusBadRequest)
		return
	}
	token, err := a.clientConfig.Exchange(a.ctx, r.URL.Query().Get("code"))
	if err != nil {
		logrus.WithError(err).Errorln("no token found")
		w.WriteHeader(http.StatusUnauthorized)
		errorMessage := r.URL.Query().Get("error")
		errorDescription := r.URL.Query().Get("error_description")
		errorMessage += "."
		if errorDescription != "" {
			errorMessage = errorMessage[:len(errorMessage)-1] + ", " + errorDescription + "."
		}
		if errorMessage != "" {
			if _, err := fmt.Fprintf(w, "%s", errorMessage); err != nil {
				logrus.WithError(err).Errorln("Could not return errorMessage")
			}
		}
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}

	idToken, err := a.provider.Verifier(oidcConfig).Verify(a.ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage
	}{token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(data); err != nil {
		logrus.WithError(err).Errorln("Can't write token information to browser")
	}
}

func main() {
	auther, err := newAuthenticator()
	if err != nil {
		logrus.WithError(err).Fatal("failed to get authenticator")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logrus.Debugln("New authentication Request submitted from " + r.Host)
		http.Redirect(w, r, auther.clientConfig.AuthCodeURL("statexyz"), http.StatusFound) //State Value is used to map Authorization Requests to Responses. Should probably be generated per Auth Request
	})

	mux.HandleFunc("/callback", auther.handleCallback)

	logrus.Fatal(http.ListenAndServe("127.0.0.1:5555", mux))
}
