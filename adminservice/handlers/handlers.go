package provider

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
)

func (s Service) AdminLoginRequestHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		logrus.WithError(err).Errorln("could not parse form")
	}

	login := r.Form["login"][0]
	password := r.Form["password"][0]

	logrus.
		WithFields(
			logrus.Fields{
				"login":    login,
				"password": password,
			}).
		Infoln("adminLogin request")

	if !s.checkPassword(login, password) {
		logrus.Info("Login attempt failed")
		http.Error(w, "Sorry, the provided login credentials do not match!", http.StatusForbidden)
		return
	}

	//Create new cookie/session
	if session, err := s.cookieStore.Get(r, "admin_auth"); err == nil {
		session.Options = &sessions.Options{
			MaxAge:   120, // 2 minutes
			HttpOnly: true,
		}
		session.Values["user"] = login

		if err := session.Save(r, w); err != nil { //TODO: Sign cookies???
			w.WriteHeader(http.StatusInternalServerError)
			logrus.Errorln("session cookie could not be written")
			return
		}

		http.Redirect(w, r, "/addClientCert", 301)
		return
	} else {
		http.Error(w, "Something went wrong while creating your session", http.StatusInternalServerError)
		return
	}
}

func (s Service) AddClientCertificateRequestHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil { // limit max input length! TODO: check
		http.Error(w, "Something went wrong!", http.StatusInternalServerError)
		logrus.WithError(err).Errorln("Could not parse multipart form")
	}
	var buf bytes.Buffer
	// in your case file would be fileupload
	certfile, header, err := r.FormFile("certfile")
	if err != nil {
		panic(err)
	}
	defer certfile.Close()
	name := strings.Split(header.Filename, ".")
	logrus.WithField("name", name[0]).Printf("File name")
	// Copy the file data to my buffer
	if _, err = io.Copy(&buf, certfile); err != nil {
		http.Error(w, "Something went wrong!", http.StatusInternalServerError)
		logrus.WithError(err).Errorln("Could not copy certfile into buffer")
		return
	}

	block, _ := pem.Decode(buf.Bytes())
	if block == nil {
		logrus.WithError(err).Errorln("pem.Decode Error")
		http.Error(w, "Unable to decode certificate. Please verify pem encoding", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	clientCert, err := x509.ParseCertificate(block.Bytes)

	clientCertHash, _ := SHA1Hash(clientCert.Raw)

	if err != nil {
		logrus.WithError(err).Errorln("Could not parse certificate")
		http.Error(w, "Could not parse certificate", http.StatusInternalServerError)
		return
	}

	rowExists := s.rowExists("SELECT username FROM users WHERE username=?", username)

	if !rowExists {
		logrus.Errorln("rowExists returned false for user " + username)
		http.Error(w, "User cannot be found in the database", http.StatusBadRequest)
		return
	} else {
		insertStatement := "INSERT INTO `devices_hashed` (`fingerprint`, `assigned_user`, `serial`) VALUES (?, ?, ?)"
		res, err := s.db.Exec(insertStatement, clientCertHash, username, clientCert.SerialNumber.String())

		if err != nil {
			logrus.WithError(err).Errorln("Could not execute sql insert statement")
			http.Error(w, "Certificate already added!", http.StatusBadRequest)
			return
		}

		if affected, err := res.RowsAffected(); err != nil {
			logrus.WithError(err).Errorln("Could not read amount of affected rows")
		} else if affected == 1 {
			if _, err := fmt.Fprintf(w, "Certificate successfully added"); err != nil {
				logrus.WithError(err).Errorln("Could not return success response")
			}
		} else {
			logrus.Errorln("Odd amount of affected rows while inserting new user")
		}
	}
}

func (s Service) AddClientCertificateHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := s.cookieStore.Get(r, "admin_auth")

	if session.IsNew {
		logrus.Info("No session found, redirecting to login page")
		http.Redirect(w, r, "/adminLogin", http.StatusMovedPermanently)
	}

	usernames := s.getAllUsers()

	fp := path.Join("views", "addCert.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, "Oops, something went wrong!", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, map[string]interface{}{"usernames": usernames}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s Service) getAllUsers() []string {
	var usernames []string
	rows, err := s.db.Query("SELECT username FROM users")

	if rows != nil {
		for rows.Next() {
			var username string
			err := rows.Scan(&username)
			if err != nil {
				log.Fatal(err)
			} else {
				usernames = append(usernames, username)
			}
		}
		err = rows.Err()
		if err != nil {
			logrus.WithError(err).Errorln("error while evaluating sql result")
		}
	}
	return usernames
}

func (s Service) AdminLoginHandler(w http.ResponseWriter, r *http.Request) {
	fp := path.Join("views", "login.html")
	http.ServeFile(w, r, fp)
}

func (s Service) checkPassword(login string, password string) bool { //TODO: Utility Function, should be extracted
	queryGetUser := "SELECT password FROM admins WHERE username=?"
	rows := s.db.QueryRow(queryGetUser, login)
	var resultPassword []byte

	if err := rows.Scan(&resultPassword); err != nil {
		logrus.WithError(err).Errorln("could not retrieve password from db/user not in database")
		return false
	}
	return bcrypt.CompareHashAndPassword(resultPassword, []byte(password)) == nil
}

func (s Service) rowExists(query string, args ...interface{}) bool {
	var exists bool
	query = fmt.Sprintf("SELECT exists (%s)", query)
	err := s.db.QueryRow(query, args...).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		logrus.WithError(err).Errorln("error checking if row exists '%s'", args)
	}
	return exists
}

func printRequest(r *http.Request) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))
}

func SHA1Hash(cert []byte) ([]byte, error) {
	h := sha1.New()
	if _, err := h.Write(cert); err != nil {
		return nil, err
	}
	hash := h.Sum(nil)
	return hash, nil
}
