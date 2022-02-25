package main

import (
	"bytes"
	"fmt"
	"github.com/RoodeyMental/goidcdt/docshare/auth"
	"github.com/RoodeyMental/goidcdt/docshare/session"
	"github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
	"html/template"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
)

type UserType string
type Right int8

const (
	internal UserType = "internal"
	external          = "external"
	customer          = "customer"
)

const (
	read Right = iota
	write
)

type Handler struct {
	store          map[int]Document
	rights         map[string]map[UserType][]Right
	sessionManager session.SessionManager
	authenticator  *auth.Authenticator
}

type Document struct {
	path string
	UserType
}

func newHandler() Handler {
	auther, _ := auth.NewAuthenticator()

	return Handler{
		sessionManager: session.NewSessionManager(),
		authenticator:  auther,
	}
}

func main() {
	mux := http.NewServeMux()
	handler := newHandler()

	handler.initializeData()

	mux.HandleFunc("/search", handler.Search)
	mux.HandleFunc("/searchRequest", handler.SearchRequest)
	mux.HandleFunc("/write", handler.Write)
	mux.HandleFunc("/writeRequest", handler.WriteRequest)
	mux.HandleFunc("/searchRequestCallback", handler.SearchRequestCallBack)
	mux.HandleFunc("/writeRequestCallback", handler.WriteRequestCallBack)

	logrus.Fatal(http.ListenAndServe("127.0.0.1:5410", mux))
}

func (h *Handler) Search(resp http.ResponseWriter, req *http.Request) {
	fp := path.Join("views", "search.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(resp, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(resp, nil); err != nil {
		http.Error(resp, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) SearchRequest(resp http.ResponseWriter, req *http.Request) {
	docIDRaw := req.URL.Query().Get("id")
	docId, err := strconv.Atoi(docIDRaw)

	if err != nil {
		logrus.WithError(err).Errorln("could not parse id")
		http.Error(resp, "Internal Error", http.StatusInternalServerError)
		return
	}

	c, err := req.Cookie("session-id")
	if err != nil || !h.sessionManager.IsSessionValid(c.Value) {
		h.sessionManager.NewPendingReadRequest(resp, docId)
		h.authenticator.RequestAuthentication("http://127.0.0.1:5410/searchRequestCallback", resp, req)
		return
	}

	document := h.store[docId]

	user := h.sessionManager.GetUser(c.Value)

	if h.isUserAuthorized(user, document.UserType, read) {
		if document, ok := h.store[docId]; ok {
			h.loadAndReturnDocument(resp, req, document)
		} else {
			logrus.WithError(err).Errorln("document not found")
			http.Error(resp, "Document not found", http.StatusNotFound)
			return
		}
	} else {
		logrus.WithError(err).Errorln("user unauthorized")
		http.Error(resp, "Unauthorized", http.StatusUnauthorized)
		return
	}
}

func (h *Handler) isUserAuthorized(user string, usertype UserType, right Right) bool {
	if userRights, ok := h.rights[user][usertype]; ok {
		for _, userRight := range userRights {
			if userRight == right {
				return true
			}
		}
	}
	return false
}

func (h *Handler) Write(resp http.ResponseWriter, req *http.Request) {
	fp := path.Join("views", "write.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(resp, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(resp, nil); err != nil {
		http.Error(resp, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) WriteRequest(resp http.ResponseWriter, req *http.Request) {
	var filename string
	var buffer bytes.Buffer
	var scope string
	var id int

	c, err := req.Cookie("request-id")
	if err != nil {
		if err := req.ParseMultipartForm(32 << 20); err != nil { // limit max input length!
			http.Error(resp, "Something went wrong!", http.StatusInternalServerError)
			logrus.WithError(err).Errorln("Could not parse multipart form")
		}
		var buf bytes.Buffer
		// in your case file would be fileupload
		document, header, err := req.FormFile("document")
		if err != nil {
			panic(err)
		}
		defer document.Close()
		name := strings.Split(header.Filename, ".")
		logrus.WithField("name", name[0]).Printf("File name")

		if _, err = io.Copy(&buf, document); err != nil {
			http.Error(resp, "Something went wrong!", http.StatusInternalServerError)
			logrus.WithError(err).Errorln("Could not copy document into buffer")
			return
		}
		filename = header.Filename
		buffer = buf
		scope = req.FormValue("scope")
		id, _ = strconv.Atoi(req.FormValue("id"))
	} else {
		request := h.sessionManager.GetPendingRequest(c.Value)
		filename = (*request).FileName
		buffer = (*request).Buffer
		scope = (*request).Scope
		id = (*request).PendingId
		h.sessionManager.SetCookie(resp, -1, "", "request-id")
	}

	sessionCookie, err := req.Cookie("session-id")
	if err != nil || !h.sessionManager.IsSessionValid(sessionCookie.Value) {
		h.sessionManager.NewPendingWriteRequest(resp, id, filename, buffer, scope)
		h.authenticator.RequestAuthentication("http://127.0.0.1:5410/writeRequestCallback", resp, req)
		return
	}

	user := h.sessionManager.GetUser(sessionCookie.Value)

	if h.isUserAuthorized(user, UserType(scope), write) {
		if doc, ok := h.store[id]; ok {
			err = os.WriteFile(path.Join("files", doc.path), buffer.Bytes(), 0644)
			if err != nil {
				logrus.WithError(err).Errorln("could not write file")
				http.Error(resp, "Internal Error", http.StatusInternalServerError)
				return
			}
			fmt.Fprint(resp, "Dokument mit der ID"+strconv.Itoa(id)+" ersetzt")
		} else {
			var nextFreeId int
			if id < 0 {
				for id := range h.store {
					nextFreeId = id
				}

				id = nextFreeId

				h.store[id] = Document{
					path:     filename,
					UserType: UserType(scope),
				}

			}
			fmt.Fprint(resp, "Neues Dokument mit ID "+strconv.Itoa(id)+" geschrieben")
		}
	} else {
		logrus.WithError(err).Errorln("user unauthorized")
		http.Error(resp, "Unauthorized", http.StatusUnauthorized)
		return
	}
}

func (h *Handler) initializeData() {
	h.rights = map[string]map[UserType][]Right{
		"ds_user_internal": {internal: {read, write}},
		"ds_user_external": {external: {read}},
		"ds_user_customer": {customer: {read, write}},
	}

	h.store = map[int]Document{
		0: {
			path:     "int.pdf",
			UserType: internal,
		},
		1: {
			path:     "ext.pdf",
			UserType: external,
		},
		2: {
			path:     "cust.pdf",
			UserType: customer,
		},
	}
}

func (h *Handler) loadAndReturnDocument(resp http.ResponseWriter, req *http.Request, document Document) {
	f, err := os.Open(path.Join("files", document.path))

	if err != nil {
		logrus.Error(err)
		resp.WriteHeader(500)
		return
	}
	defer f.Close()

	//Set header
	resp.Header().Set("Content-type", "application/pdf")

	//Stream to response
	if _, err := io.Copy(resp, f); err != nil {
		fmt.Println(err)
		resp.WriteHeader(500)
	}
}

func (h *Handler) SearchRequestCallBack(w http.ResponseWriter, r *http.Request) {
	token := h.extractIDToken(w, r, "http://127.0.0.1:5410/searchRequestCallback")

	if token == nil {
		return
	}

	h.sessionManager.NewSession(w, token)

	c, _ := r.Cookie("request-id")

	h.sessionManager.SetCookie(w, -1, "", "request-id")
	request := h.sessionManager.GetPendingRequest(c.Value)

	http.Redirect(w, r, "http://127.0.0.1:5410/searchRequest?id="+strconv.Itoa((*request).PendingId), http.StatusFound)
}

func (h *Handler) WriteRequestCallBack(w http.ResponseWriter, r *http.Request) {
	token := h.extractIDToken(w, r, "http://127.0.0.1:5410/writeRequestCallback")

	if token == nil {
		return
	}

	h.sessionManager.NewSession(w, token)

	http.Redirect(w, r, "http://127.0.0.1:5410/writeRequest", http.StatusFound)
}

func (h *Handler) extractIDToken(w http.ResponseWriter, r *http.Request, callbackUrl string) *oidc.IDToken {
	logrus.WithField("host", r.Host).Debugln("New Callback from")
	if r.URL.Query().Get("state") != "statexyz" {
		http.Error(w, "statexyz did not match", http.StatusBadRequest)
		return nil
	}
	h.authenticator.ClientConfig.RedirectURL = callbackUrl
	token, err := h.authenticator.ClientConfig.Exchange(h.authenticator.Ctx, r.URL.Query().Get("code"))

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
		return nil
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return nil
	}

	oidcConfig := &oidc.Config{
		ClientID: "docshare",
	}

	if idToken, err := h.authenticator.Provider.Verifier(oidcConfig).Verify(h.authenticator.Ctx, rawIDToken); err == nil {
		return idToken
	} else {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return nil
	}
}
