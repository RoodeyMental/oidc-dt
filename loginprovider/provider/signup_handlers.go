package provider

import (
	"database/sql"
	"fmt"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
	"path"
)

func (s Service) SignUpHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()

	if err != nil {
		logrus.WithError(err).Errorln("could not parse form")
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(r.Form["password"][0]), 8)

	if err != nil {
		logrus.WithError(err).Errorln("could not create hash from given password")
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}

	newUser := User{
		username:     r.Form["username"][0],
		passwordHash: string(hashedPassword),
		email:        r.Form["email"][0],
		name:         r.Form["name"][0],
		family_name:  r.Form["family_name"][0],
	}

	rowExists := s.rowExists("SELECT username FROM users WHERE username=?", newUser.username)

	if rowExists {
		http.Error(w, "User already exists!", http.StatusConflict)
	} else {
		insertStatement := "INSERT INTO `users` (`username`, `email`, `password`, `name`, `family_name`) VALUES (?, ?, ?, ?, ?)"
		res, err := s.db.Exec(insertStatement, newUser.username, newUser.email, newUser.passwordHash, newUser.name, newUser.family_name)

		if err != nil {
			logrus.WithError(err).Errorln("Could not execute sql insert statement")
		}
		if affected, err := res.RowsAffected(); err != nil {
			logrus.WithError(err).Errorln("Could not read amount of affected rows")
		} else if affected == 1 {
			if _, err := fmt.Fprintf(w, "User successfully added"); err != nil {
				logrus.WithError(err).Errorln("Unable to return error")
			}
		} else {
			logrus.Errorln("Odd ammount of affected rows while inserting new user")
		}
	}
}

func (s Service) IndexHandler(w http.ResponseWriter, r *http.Request) {
	fp := path.Join("views", "signup.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s Service) rowExists(query string, args ...interface{}) bool {
	var exists bool
	query = fmt.Sprintf("SELECT exists (%s)", query)
	err := s.db.QueryRow(query, args...).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		logrus.WithError(err).Errorln("error checking if row exists '%s'", args)
		return false
	}
	return exists
}
