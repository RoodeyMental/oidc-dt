package provider

import (
	"bytes"
	"fmt"
	"github.com/RoodeyMental/goidcdt/loginprovider/util"
	"github.com/sirupsen/logrus"
)

func (s Service) checkCertificate(certificate []byte) bool {
	queryGetDevices := "SELECT fingerprint FROM devices_hashed WHERE fingerprint=?"
	rows, err := s.db.Query(queryGetDevices, certificate)
	var devices [][]byte

	if rows != nil {
		for rows.Next() {
			var resultFingerprint []byte
			err := rows.Scan(&resultFingerprint)
			if err != nil {
				logrus.Fatal(err)
			} else {
				devices = append(devices, resultFingerprint)
			}
		}
		err = rows.Err()
		if err != nil {
			logrus.WithError(err).Errorln("error while evaluating sql result")
			return false
		}
	}
	fmt.Println(certificate)

	containsDevice := false
	for _, device := range devices {
		if bytes.Equal(certificate, device) {
			containsDevice = true
			break
		}
	}
	return containsDevice
}

func (s Service) checkCertificateByUser(certificate []byte, username string) bool {
	queryGetDevices := "SELECT fingerprint FROM devices_hashed WHERE assigned_user=?"
	rows, err := s.db.Query(queryGetDevices, username)
	var devices [][]byte

	if rows != nil {
		for rows.Next() {
			var resultFingerprint []byte
			err := rows.Scan(&resultFingerprint)
			if err != nil {
				logrus.Fatal(err)
			} else {
				devices = append(devices, resultFingerprint)
			}
		}
		err = rows.Err()
		if err != nil {
			logrus.WithError(err).Errorln("error while evaluating sql result")
			return false
		}
	}

	fmt.Println(certificate)
	containsDevice := false
	if certificateHashed, err := util.SHA1Hash(certificate); err == nil {
		for _, device := range devices {
			if bytes.Equal(certificateHashed, device) {
				containsDevice = true
				break
			}
		}
	} else {
		logrus.WithError(err).Errorln("error hashing evaluating sql result")
		return false
	}

	return containsDevice
}
