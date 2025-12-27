/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/fabric/internal/cryptogen/csp"
	"github.com/pkg/errors"
	gmsmSM2 "github.com/tjfoc/gmsm/sm2"
	gmsmX509 "github.com/tjfoc/gmsm/x509"
)

type Algorithm string

const (
	AlgorithmECDSA Algorithm = "ecdsa"
	AlgorithmSM2   Algorithm = "sm2"
)

type CA struct {
	Name               string
	Country            string
	Province           string
	Locality           string
	OrganizationalUnit string
	StreetAddress      string
	PostalCode         string
	Signer             crypto.Signer
	Algorithm          Algorithm

	// SignCertDER holds the CA certificate in ASN.1 DER format.
	SignCertDER []byte

	// SignCert is only populated for ECDSA CAs.
	SignCert *x509.Certificate

	// SignCertSM2 is only populated for SM2 CAs.
	SignCertSM2 *gmsmX509.Certificate
}

func (ca *CA) CertBytes() []byte {
	return ca.SignCertDER
}

// NewCA creates an instance of CA and saves the signing key pair in
// baseDir/name
func NewCA(
	baseDir,
	org,
	name,
	country,
	province,
	locality,
	orgUnit,
	streetAddress,
	postalCode string,
) (*CA, error) {
	var ca *CA

	err := os.MkdirAll(baseDir, 0o755)
	if err != nil {
		return nil, err
	}

	priv, err := csp.GeneratePrivateKey(baseDir)
	if err != nil {
		return nil, err
	}

	template := x509Template()
	// this is a CA
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageDigitalSignature |
		x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageServerAuth,
	}

	// set the organization for the subject
	subject := subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode)
	subject.Organization = []string{org}
	subject.CommonName = name

	template.Subject = subject
	template.SubjectKeyId = computeSKI(priv)

	x509Cert, certDER, err := genCertificateECDSA(
		baseDir,
		name,
		&template,
		&template,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		return nil, err
	}
	ca = &CA{
		Name: name,
		Signer: &csp.ECDSASigner{
			PrivateKey: priv,
		},
		Algorithm:          AlgorithmECDSA,
		SignCertDER:        certDER,
		SignCert:           x509Cert,
		Country:            country,
		Province:           province,
		Locality:           locality,
		OrganizationalUnit: orgUnit,
		StreetAddress:      streetAddress,
		PostalCode:         postalCode,
	}

	return ca, err
}

// NewCASM2 creates an instance of CA backed by SM2/SM3 for signing MSP identity material.
// Note: this is intended for MSP identity (not TLS).
func NewCASM2(
	baseDir,
	org,
	name,
	country,
	province,
	locality,
	orgUnit,
	streetAddress,
	postalCode string,
) (*CA, error) {
	err := os.MkdirAll(baseDir, 0o755)
	if err != nil {
		return nil, err
	}

	priv, err := csp.GeneratePrivateKeySM2(baseDir)
	if err != nil {
		return nil, err
	}

	template := x509TemplateSM2()
	template.IsCA = true
	template.KeyUsage |= gmsmX509.KeyUsageDigitalSignature |
		gmsmX509.KeyUsageKeyEncipherment | gmsmX509.KeyUsageCertSign |
		gmsmX509.KeyUsageCRLSign
	template.ExtKeyUsage = []gmsmX509.ExtKeyUsage{
		gmsmX509.ExtKeyUsageClientAuth,
		gmsmX509.ExtKeyUsageServerAuth,
	}

	subject := subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode)
	subject.Organization = []string{org}
	subject.CommonName = name

	template.Subject = subject
	template.SubjectKeyId = computeSKISM2(priv)
	template.SignatureAlgorithm = gmsmX509.SM2WithSM3

	sm2Cert, certDER, err := genCertificateSM2(
		baseDir,
		name,
		&template,
		&template,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		return nil, err
	}

	return &CA{
		Name:               name,
		Signer:             priv,
		Algorithm:          AlgorithmSM2,
		SignCertDER:        certDER,
		SignCertSM2:        sm2Cert,
		Country:            country,
		Province:           province,
		Locality:           locality,
		OrganizationalUnit: orgUnit,
		StreetAddress:      streetAddress,
		PostalCode:         postalCode,
	}, nil
}

// SignCertificate creates a signed certificate based on a built-in template
// and saves it in baseDir/name
func (ca *CA) SignCertificate(
	baseDir,
	name string,
	orgUnits,
	alternateNames []string,
	pub crypto.PublicKey,
	ku x509.KeyUsage,
	eku []x509.ExtKeyUsage,
) ([]byte, error) {
	if ca.Algorithm == AlgorithmSM2 {
		return ca.signCertificateSM2(baseDir, name, orgUnits, alternateNames, pub, ku, eku)
	}
	return ca.signCertificateECDSA(baseDir, name, orgUnits, alternateNames, pub, ku, eku)
}

func (ca *CA) signCertificateECDSA(
	baseDir,
	name string,
	orgUnits,
	alternateNames []string,
	pub crypto.PublicKey,
	ku x509.KeyUsage,
	eku []x509.ExtKeyUsage,
) ([]byte, error) {
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("expected ECDSA public key")
	}
	template := x509Template()
	template.KeyUsage = ku
	template.ExtKeyUsage = eku

	// set the organization for the subject
	subject := subjectTemplateAdditional(
		ca.Country,
		ca.Province,
		ca.Locality,
		ca.OrganizationalUnit,
		ca.StreetAddress,
		ca.PostalCode,
	)
	subject.CommonName = name

	subject.OrganizationalUnit = append(subject.OrganizationalUnit, orgUnits...)

	template.Subject = subject
	for _, san := range alternateNames {
		// try to parse as an IP address first
		ip := net.ParseIP(san)
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	_, certDER, err := genCertificateECDSA(
		baseDir,
		name,
		&template,
		ca.SignCert,
		ecdsaPub,
		ca.Signer,
	)
	if err != nil {
		return nil, err
	}

	return certDER, nil
}

func (ca *CA) signCertificateSM2(
	baseDir,
	name string,
	orgUnits,
	alternateNames []string,
	pub crypto.PublicKey,
	ku x509.KeyUsage,
	eku []x509.ExtKeyUsage,
) ([]byte, error) {
	sm2Pub, ok := pub.(*gmsmSM2.PublicKey)
	if !ok {
		return nil, errors.New("expected SM2 public key")
	}

	template := x509TemplateSM2()
	template.KeyUsage = gmsmX509.KeyUsage(ku)
	template.ExtKeyUsage = make([]gmsmX509.ExtKeyUsage, 0, len(eku))
	for _, usage := range eku {
		template.ExtKeyUsage = append(template.ExtKeyUsage, gmsmX509.ExtKeyUsage(usage))
	}
	template.SignatureAlgorithm = gmsmX509.SM2WithSM3

	subject := subjectTemplateAdditional(
		ca.Country,
		ca.Province,
		ca.Locality,
		ca.OrganizationalUnit,
		ca.StreetAddress,
		ca.PostalCode,
	)
	subject.CommonName = name
	subject.OrganizationalUnit = append(subject.OrganizationalUnit, orgUnits...)
	template.Subject = subject

	for _, san := range alternateNames {
		ip := net.ParseIP(san)
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	_, certDER, err := genCertificateSM2(
		baseDir,
		name,
		&template,
		ca.SignCertSM2,
		sm2Pub,
		ca.Signer,
	)
	if err != nil {
		return nil, err
	}

	return certDER, nil
}

// compute Subject Key Identifier using RFC 7093, Section 2, Method 4
func computeSKI(privKey *ecdsa.PrivateKey) []byte {
	// Marshall the public key
	raw := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)

	// Hash it
	hash := sha256.Sum256(raw)
	return hash[:]
}

func computeSKISM2(privKey *gmsmSM2.PrivateKey) []byte {
	raw := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)
	hash := sha256.Sum256(raw)
	return hash[:]
}

// default template for X509 subject
func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"US"},
		Locality: []string{"San Francisco"},
		Province: []string{"California"},
	}
}

// Additional for X509 subject
func subjectTemplateAdditional(
	country,
	province,
	locality,
	orgUnit,
	streetAddress,
	postalCode string,
) pkix.Name {
	name := subjectTemplate()
	if len(country) >= 1 {
		name.Country = []string{country}
	}
	if len(province) >= 1 {
		name.Province = []string{province}
	}

	if len(locality) >= 1 {
		name.Locality = []string{locality}
	}
	if len(orgUnit) >= 1 {
		name.OrganizationalUnit = []string{orgUnit}
	}
	if len(streetAddress) >= 1 {
		name.StreetAddress = []string{streetAddress}
	}
	if len(postalCode) >= 1 {
		name.PostalCode = []string{postalCode}
	}
	return name
}

// default template for X509 certificates
func x509Template() x509.Certificate {
	// generate a serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	// set expiry to around 10 years
	expiry := 3650 * 24 * time.Hour
	// round minute and backdate 5 minutes
	notBefore := time.Now().Round(time.Minute).Add(-5 * time.Minute).UTC()

	// basic template to use
	x509 := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(expiry).UTC(),
		BasicConstraintsValid: true,
	}
	return x509
}

func x509TemplateSM2() gmsmX509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	expiry := 3650 * 24 * time.Hour
	notBefore := time.Now().Round(time.Minute).Add(-5 * time.Minute).UTC()

	return gmsmX509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(expiry).UTC(),
		BasicConstraintsValid: true,
	}
}

// generate a signed X509 certificate using ECDSA
func genCertificateECDSA(
	baseDir,
	name string,
	template,
	parent *x509.Certificate,
	pub *ecdsa.PublicKey,
	priv interface{},
) (*x509.Certificate, []byte, error) {
	// create the x509 public cert
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	// write cert out to file
	fileName := filepath.Join(baseDir, name+"-cert.pem")
	certFile, err := os.Create(fileName)
	if err != nil {
		return nil, nil, err
	}
	// pem encode the cert
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certFile.Close()
	if err != nil {
		return nil, nil, err
	}

	x509Cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return x509Cert, certBytes, nil
}

func genCertificateSM2(
	baseDir,
	name string,
	template,
	parent *gmsmX509.Certificate,
	pub *gmsmSM2.PublicKey,
	priv crypto.Signer,
) (*gmsmX509.Certificate, []byte, error) {
	certBytes, err := gmsmX509.CreateCertificate(template, parent, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	fileName := filepath.Join(baseDir, name+"-cert.pem")
	certFile, err := os.Create(fileName)
	if err != nil {
		return nil, nil, err
	}
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certFile.Close()
	if err != nil {
		return nil, nil, err
	}

	sm2Cert, err := gmsmX509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return sm2Cert, certBytes, nil
}

// LoadCertificateECDSA load a ecdsa cert from a file in cert path
func LoadCertificateECDSA(certPath string) (*x509.Certificate, error) {
	var cert *x509.Certificate
	var err error

	walkFunc := func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".pem") {
			rawCert, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			block, _ := pem.Decode(rawCert)
			if block == nil || block.Type != "CERTIFICATE" {
				return errors.Errorf("%s: wrong PEM encoding", path)
			}
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return errors.Errorf("%s: wrong DER encoding", path)
			}
		}
		return nil
	}

	err = filepath.Walk(certPath, walkFunc)
	if err != nil {
		return nil, err
	}

	return cert, err
}

// LoadCertificateSM2 loads a SM2 certificate from a PEM file under certPath.
func LoadCertificateSM2(certPath string) (*gmsmX509.Certificate, []byte, error) {
	var cert *gmsmX509.Certificate
	var certDER []byte

	walkFunc := func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".pem") {
			rawCert, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			block, _ := pem.Decode(rawCert)
			if block == nil || block.Type != "CERTIFICATE" {
				return errors.Errorf("%s: wrong PEM encoding", path)
			}
			certDER = block.Bytes
			cert, err = gmsmX509.ParseCertificate(block.Bytes)
			if err != nil {
				return errors.Errorf("%s: wrong DER encoding", path)
			}
		}
		return nil
	}

	err := filepath.Walk(certPath, walkFunc)
	if err != nil {
		return nil, nil, err
	}

	return cert, certDER, nil
}
