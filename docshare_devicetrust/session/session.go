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
	token             *oidc.IDToken
	isCallbackRequest bool
}

type DocshareClaims struct {
	Result map[string]string `json:"docshare_dt"`
}

type DeviceClaims struct {
	DeviceAuth  string `json:"device_auth"`
	DeviceTrust string `json:"device_trust"`
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

func (s SessionManager) NewSession(w http.ResponseWriter) string {
	uid := ksuid.New().String()
	session := Session{}
	s.sessionStore[uid] = &session
	s.SetCookie(w, int(100), uid, "session-id")
	return uid
}

func (s SessionManager) AddTokenToSession(w http.ResponseWriter, sessionID string, token *oidc.IDToken) {
	s.sessionStore[sessionID].token = token
	maxAge := token.Expiry.Sub(time.Now()).Seconds()
	s.SetCookie(w, int(maxAge), sessionID, "session-id")
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

func (s SessionManager) SetCallbackFlag(sessionId string, flag bool) {
	s.sessionStore[sessionId].isCallbackRequest = flag
}

func (s SessionManager) GetClaims(cookie string) (DocshareClaims, DeviceClaims) {
	var claims DocshareClaims
	var deviceClaims DeviceClaims
	s.sessionStore[cookie].token.Claims(&claims)
	s.sessionStore[cookie].token.Claims(&deviceClaims)
	return claims, deviceClaims
}

func (s SessionManager) GetPendingRequest(cookie string) *PendingRequest {
	return s.pendingRequestStore[cookie]
}

func (s SessionManager) IsSessionValid(w http.ResponseWriter, cookie *http.Cookie) bool {
	if cookie == nil {
		s.NewSession(w)
		return false
	}

	if val, ok := s.sessionStore[cookie.Value]; ok {
		if val.token.Expiry.After(time.Now()) && val.isCallbackRequest {
			s.SetCallbackFlag(cookie.Value, false)
			return true
		}
	}
	return false
}
