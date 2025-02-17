package cert

import (
	"math/big"
	"os"
	"strings"
	"testing"
)

func TestVerifyCertificateChain(t *testing.T) {
	// Create a CA and certificate for testing
	ca := &CACert{
		Serial:        big.NewInt(1),
		ValidForYears: 1,
		Subject: CertSubject{
			Country:    "US",
			CommonName: "Test CA",
		},
	}

	// Create temporary CA files
	caKeyFile, err := os.CreateTemp("", "ca-*.key")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(caKeyFile.Name())

	caCertFile, err := os.CreateTemp("", "ca-*.crt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(caCertFile.Name())

	// Create CA
	if err := CreateCACert(ca, caKeyFile.Name(), caCertFile.Name()); err != nil {
		t.Fatal(err)
	}

	// Read CA materials
	caCert, err := os.ReadFile(caCertFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := os.ReadFile(caKeyFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	// Create a test certificate
	cert := &Cert{
		Serial:        big.NewInt(2),
		ValidForYears: 1,
		Subject: CertSubject{
			Country:    "US",
			CommonName: "test.example.com",
		},
	}

	// Create temporary cert files
	certKeyFile, err := os.CreateTemp("", "cert-*.key")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(certKeyFile.Name())

	certFile, err := os.CreateTemp("", "cert-*.crt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(certFile.Name())

	// Create certificate
	if err := CreateCert(cert, caKey, caCert, certKeyFile.Name(), certFile.Name()); err != nil {
		t.Fatal(err)
	}

	// Read the certificate
	certPEM, err := os.ReadFile(certFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		certPEM     []byte
		caCertPEM   []byte
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid chain",
			certPEM:   certPEM,
			caCertPEM: caCert,
			wantErr:   false,
		},
		{
			name:        "invalid CA cert",
			certPEM:     certPEM,
			caCertPEM:   []byte("invalid"),
			wantErr:     true,
			errContains: "failed to parse CA certificate",
		},
		{
			name:        "invalid cert",
			certPEM:     []byte("invalid"),
			caCertPEM:   caCert,
			wantErr:     true,
			errContains: "failed to parse certificate PEM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyCertificateChain(tt.certPEM, tt.caCertPEM)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyCertificateChain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
			}
		})
	}
}
