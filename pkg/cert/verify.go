package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// VerifyCertificateChain verifies that a certificate was signed by the given CA certificate
func VerifyCertificateChain(certPEM, caCertPEM []byte) error {
	// Parse CA certificate
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCertPEM) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	// Parse certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Verify the certificate against the CA
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	// Log chain information for debugging
	for i, chain := range chains {
		for j, cert := range chain {
			fmt.Printf("Chain %d Certificate %d: Subject: %s, Issuer: %s\n",
				i, j, cert.Subject.CommonName, cert.Issuer.CommonName)
		}
	}

	return nil
}
