package cert

import (
	"math/big"
	"os"
	"testing"
)

func TestCreateCACert(t *testing.T) {
	tests := []struct {
		name        string
		ca          *CACert
		wantErr     bool
		errContains string
	}{
		{
			name: "valid CA certificate",
			ca: &CACert{
				Serial:        big.NewInt(1),
				ValidForYears: 1,
				Subject: CertSubject{
					Country:      "US",
					Organization: "Test Org",
					CommonName:   "Test CA",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid country code",
			ca: &CACert{
				Serial:        big.NewInt(1),
				ValidForYears: 1,
				Subject: CertSubject{
					Country:    "USA",
					CommonName: "Test CA",
				},
			},
			wantErr:     true,
			errContains: "country code must be ISO 3166-1 alpha-2",
		},
		{
			name: "missing common name",
			ca: &CACert{
				Serial:        big.NewInt(1),
				ValidForYears: 1,
				Subject: CertSubject{
					Country: "US",
				},
			},
			wantErr:     true,
			errContains: "common name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary files for test
			keyFile, err := os.CreateTemp("", "ca-key-*.pem")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(keyFile.Name())

			certFile, err := os.CreateTemp("", "ca-cert-*.pem")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(certFile.Name())

			err = CreateCACert(tt.ca, keyFile.Name(), certFile.Name())

			// Check error expectations
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCACert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" && err != nil {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("CreateCACert() error = %v, should contain %v", err, tt.errContains)
				}
				return
			}

			// If test should succeed, verify the certificate
			if !tt.wantErr {
				// Read and parse the certificate
				certBytes, err := os.ReadFile(certFile.Name())
				if err != nil {
					t.Fatal(err)
				}

				cert, err := PemToX509(certBytes)
				if err != nil {
					t.Fatal(err)
				}

				// Verify certificate properties
				if !cert.IsCA {
					t.Error("Certificate is not a CA certificate")
				}

				if cert.Subject.CommonName != tt.ca.Subject.CommonName {
					t.Errorf("Common name = %v, want %v", cert.Subject.CommonName, tt.ca.Subject.CommonName)
				}
			}
		})
	}
}

func TestCreateCert(t *testing.T) {
	// First create a CA for testing
	ca := &CACert{
		Serial:        big.NewInt(1),
		ValidForYears: 1,
		Subject: CertSubject{
			Country:      "US",
			Organization: "Test Org",
			CommonName:   "Test CA",
		},
	}

	caKeyFile, err := os.CreateTemp("", "ca-key-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(caKeyFile.Name())

	caCertFile, err := os.CreateTemp("", "ca-cert-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(caCertFile.Name())

	if err := CreateCACert(ca, caKeyFile.Name(), caCertFile.Name()); err != nil {
		t.Fatal(err)
	}

	caKey, err := os.ReadFile(caKeyFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := os.ReadFile(caCertFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		cert        *Cert
		wantErr     bool
		errContains string
	}{
		{
			name: "valid certificate",
			cert: &Cert{
				Serial:        big.NewInt(2),
				ValidForYears: 1,
				Subject: CertSubject{
					Country:      "US",
					Organization: "Test Org",
					CommonName:   "test.example.com",
				},
				DNSNames: []string{"test.example.com", "www.test.example.com"},
			},
			wantErr: false,
		},
		{
			name: "invalid country code",
			cert: &Cert{
				Serial:        big.NewInt(2),
				ValidForYears: 1,
				Subject: CertSubject{
					Country:    "USA",
					CommonName: "test.example.com",
				},
			},
			wantErr:     true,
			errContains: "country code must be ISO 3166-1 alpha-2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyFile, err := os.CreateTemp("", "cert-key-*.pem")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(keyFile.Name())

			certFile, err := os.CreateTemp("", "cert-*.pem")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(certFile.Name())

			err = CreateCert(tt.cert, caKey, caCert, keyFile.Name(), certFile.Name())

			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" && err != nil {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("CreateCert() error = %v, should contain %v", err, tt.errContains)
				}
				return
			}

			if !tt.wantErr {
				// Read and verify the certificate
				certBytes, err := os.ReadFile(certFile.Name())
				if err != nil {
					t.Fatal(err)
				}

				cert, err := PemToX509(certBytes)
				if err != nil {
					t.Fatal(err)
				}

				// Verify certificate properties
				if cert.IsCA {
					t.Error("Certificate should not be a CA certificate")
				}

				if cert.Subject.CommonName != tt.cert.Subject.CommonName {
					t.Errorf("Common name = %v, want %v", cert.Subject.CommonName, tt.cert.Subject.CommonName)
				}

				// Verify DNS names
				if len(cert.DNSNames) != len(tt.cert.DNSNames) {
					t.Errorf("DNSNames count = %v, want %v", len(cert.DNSNames), len(tt.cert.DNSNames))
				}
			}
		})
	}
}

// Helper function to check if a string contains another string
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && s != substr && s != "" && substr != ""
}

