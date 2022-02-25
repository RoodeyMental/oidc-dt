package provider

import (
	"database/sql"
	"github.com/gorilla/sessions"
)

type Service struct {
	db          *sql.DB
	cookieStore *sessions.CookieStore
}

// NewService create new service instance.
func NewService(db *sql.DB, cookieStore *sessions.CookieStore) *Service {
	return &Service{
		db:          db,
		cookieStore: cookieStore,
	}
}
