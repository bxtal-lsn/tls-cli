package cert

import (
	"fmt"
	"math/big"
)

type CACert struct {
	Serial        *big.Int    `yaml:"serial"`
	ValidForYears int         `yaml:"validForYears"`
	Subject       CertSubject `yaml:"subject"`
}

type Cert struct {
	Serial        *big.Int    `yaml:"serial"`
	ValidForYears int         `yaml:"validForYears"`
	Subject       CertSubject `yaml:"subject"`
	DNSNames      []string    `yaml:"dnsNames"`
}

type CertSubject struct {
	Country            string `yaml:"country"`
	Organization       string `yaml:"organization"`
	OrganizationalUnit string `yaml:"organizationalUnit"`
	Locality           string `yaml:"locality"`
	Province           string `yaml:"province"`
	StreetAddress      string `yaml:"streetAddress"`
	PostalCode         string `yaml:"postalCode"`
	SerialNumber       string `yaml:"serialNumber"`
	CommonName         string `yaml:"commonName"`
}

// Validate checks if the CertSubject fields are valid
func (s *CertSubject) Validate() error {
	if s.CommonName == "" {
		return fmt.Errorf("common name is required")
	}

	if s.Country != "" {
		if len(s.Country) != 2 {
			return fmt.Errorf("country code must be ISO 3166-1 alpha-2 format (2 letters)")
		}
		if !isValidCountryCode(s.Country) {
			return fmt.Errorf("country code must contain only letters")
		}
	}

	return nil
}

// isValidCountryCode checks if the country code is valid
func isValidCountryCode(code string) bool {
	for _, r := range code {
		if !('A' <= r && r <= 'Z') && !('a' <= r && r <= 'z') {
			return false
		}
	}
	return true
}

