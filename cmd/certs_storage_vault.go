// +build vault

package cmd

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/log"
	"github.com/urfave/cli"
)

type CertificatesStorage struct {
	Client *vaultClient
}

// NewCertificatesStorage create a new certificates storage.
func NewCertificatesStorage(ctx *cli.Context) *CertificatesStorage {
	return &CertificatesStorage{
		Client: NewVaultClient(ctx.GlobalString("")),
	}
}

func (s *CertificatesStorage) CreateRootFolder() {}

func (s *CertificatesStorage) CreateArchiveFolder() {}

func (s *CertificatesStorage) GetRootPath() string {
	return ""
}

func (s *CertificatesStorage) SaveResource(certRes *certificate.Resource) {
	domain := certRes.Domain

	c, err := s.Client.Get()
	if err != nil {
		log.Fatalf("vault: client: %s", err)
	}

	// We store the certificate, private key and metadata in different files
	// as web servers would not be able to work with a combined file.
	_, err = c.Logical().Write(
		fmt.Sprintf("secret/data/fabio/certs/%s", domain),
		map[string]interface{}{
			"cert": certRes.Certificate,
			"key": certRes.PrivateKey,
			"issuer": certRes.IssuerCertificate,
		},
	)
	if err != nil {
		log.Fatalf("Unable to save Certificate for domain %s\n\t%v", domain, err)
	}

	jsonBytes, err := json.MarshalIndent(certRes, "", "\t")
	if err != nil {
		log.Fatalf("Unable to marshal CertResource for domain %s\n\t%v", domain, err)
	}

	_, err = c.Logical().Write(
		fmt.Sprintf("secret/data/fabio/json/%s", domain),
		map[string]interface{}{
			"data": jsonBytes,
		},
	)
	if err != nil {
		log.Fatalf("Unable to save CertResource for domain %s\n\t%v", domain, err)
	}
}

func (s *CertificatesStorage) ReadResource(domain string) certificate.Resource {
	c, err := s.Client.Get()
	if err != nil {
		log.Fatalf("vault: client: %s", err)
	}

	resp, err := c.Logical().Read(
		fmt.Sprintf("secret/data/fabio/json/%s", domain),
	)
	if err != nil {
		log.Fatalf("Error while loading the meta data for domain %s\n\t%v", domain, err)
	}

	var resource certificate.Resource
	if err = json.Unmarshal(resp.Data["data"].([]byte), &resource); err != nil {
		log.Fatalf("Error while marshaling the meta data for domain %s\n\t%v", domain, err)
	}

	return resource
}

func (s *CertificatesStorage) ExistsFile(domain, extension string) bool {
	c, err := s.Client.Get()
	if err != nil {
		log.Fatalf("vault: client: %s", err)
	}

	resp, err := c.Logical().Read(
		fmt.Sprintf("secret/data/fabio/json/%s", domain),
	)
	if err != nil || resp == nil {
		return false
	}

	return true
}

func (s *CertificatesStorage) ReadFile(domain, extension string) ([]byte, error) {
	res := s.ReadResource(domain)
	switch extension {
	case ".crt":
		return res.Certificate, nil
	case ".key":
		return res.PrivateKey, nil
	default:
		return nil, fmt.Errorf("can't find certificate")
	}
}

func (s *CertificatesStorage) ReadCertificate(domain, extension string) ([]*x509.Certificate, error) {
	content, err := s.ReadFile(domain, extension)
	if err != nil {
		return nil, err
	}

	// The input may be a bundle or a single certificate.
	return certcrypto.ParsePEMBundle(content)
}

func (s *CertificatesStorage) WriteFile(domain, extension string, data []byte) error {
	return nil
}

func (s *CertificatesStorage) MoveToArchive(domain string) error {
	return nil
}
