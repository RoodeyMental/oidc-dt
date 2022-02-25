package session

import (
	"bytes"
	oidc "github.com/coreos/go-oidc"
	"github.com/segmentio/ksuid"
	"net/http"
	"time"
)

type SessionManager struct {
	sessionStore        map[string]*Session
	pendingRequestStore map[string]*PendingRequest
}

type Session struct {
	token *oidc.IDToken
}

type PendingRequest struct {
	PendingId int
	FileName  string
	Scope     string
	Buffer    bytes.Buffer
}

func (s SessionManager) SetCookie(w http.ResponseWriter, maxAge int, id string, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  id,
		Path:   "/",
		MaxAge: maxAge,
	})
}

func (s SessionManager) NewSession(w http.ResponseWriter, token *oidc.IDToken) {
	uid := ksuid.New().String()
	session := Session{
		token: token,
	}
	s.sessionStore[uid] = &session
	maxAge := token.Expiry.Sub(time.Now()).Seconds()
	s.SetCookie(w, int(maxAge), uid, "session-id")
}

func (s SessionManager) NewPendingReadRequest(w http.ResponseWriter, id int) {
	uid := ksuid.New().String()
	request := PendingRequest{
		PendingId: id,
	}
	s.pendingRequestStore[uid] = &request
	maxAge := 10000
	s.SetCookie(w, maxAge, uid, "request-id")
}

func (s SessionManager) NewPendingWriteRequest(w http.ResponseWriter, id int, filename string, buffer bytes.Buffer, scope string) {
	uid := ksuid.New().String()
	request := PendingRequest{
		PendingId: id,
		FileName:  filename,
		Buffer:    buffer,
		Scope:     scope,
	}
	s.pendingRequestStore[uid] = &request
	maxAge := 10000
	s.SetCookie(w, maxAge, uid, "request-id")
}

func NewSessionManager() SessionManager {
	return SessionManager{
		sessionStore:        make(map[string]*Session),
		pendingRequestStore: make(map[string]*PendingRequest),
	}
}

func (s SessionManager) GetUser(cookie string) string {
	return s.sessionStore[cookie].token.Subject
}

func (s SessionManager) GetPendingRequest(cookie string) *PendingRequest {
	return s.pendingRequestStore[cookie]
}

func (s SessionManager) IsSessionValid(cookie string) bool {
	if val, ok := s.sessionStore[cookie]; ok {
		return val.token.Expiry.After(time.Now())
	} else {
		return false
	}
}
