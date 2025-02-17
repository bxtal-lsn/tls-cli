# TLS Certificate Management Tool

A command-line tool written in Go for managing TLS certificates, including creation of Certificate Authorities (CA) and end-entity certificates. This tool simplifies the process of creating and managing a PKI (Public Key Infrastructure) for development and testing purposes.

## Features

- Create and manage Certificate Authorities (CA)
- Generate server and client certificates
- RSA key generation with configurable key lengths
- YAML-based configuration for certificate templates
- Support for multiple Subject Alternative Names (SANs)
- TLS 1.3 support
- Client certificate authentication support

## Prerequisites

- Go 1.18 or higher
- OpenSSL (optional, for certificate verification)

## Installation

```bash
# Build the binary
go build -o tls
```

## Quick Start

1. Create a configuration file (`tls.yaml`):
```yaml
caCert:
  serial: 1
  validForYears: 10
  subject:
    country: US
    organization: My Organization
    organizationalUnit: Certificate Management
    locality: New York
    commonName: My Root CA

certs:
  server.example.com:
    serial: 1
    validForYears: 1
    dnsNames: ["server.example.com", "www.server.example.com"]
    subject:
      country: US
      organization: My Organization
      organizationalUnit: Web Services
      locality: New York
      commonName: server.example.com
```

2. Create a CA:
```bash
./tls create ca --key-out ca.key --cert-out ca.crt
```

3. Create a server certificate:
```bash
./tls create cert --name server.example.com --key-out server.key --cert-out server.crt --ca-key ca.key --ca-cert ca.crt
```

## Command Reference

### Global Flags
- `-c, --config`: Configuration file path (default: "tls.yaml")

### Create CA
```bash
./tls create ca [flags]

Flags:
  -k, --key-out string    Destination path for CA key (default: "ca.key")
  -o, --cert-out string   Destination path for CA certificate (default: "ca.crt")
```

### Create Certificate
```bash
./tls create cert [flags]

Flags:
  -k, --key-out string    Destination path for certificate key (default: "server.key")
  -o, --cert-out string   Destination path for certificate (default: "server.crt")
  -n, --name string       Name of the certificate in the config file (required)
      --ca-key string     CA key to sign certificate (default: "ca.key")
      --ca-cert string    CA certificate (default: "ca.crt")
```

### Create RSA Key
```bash
./tls create key [flags]

Flags:
  -k, --key-out string      Destination path for key (default: "key.pem")
  -l, --key-length int      Key length in bits (default: 4096)
```

## Configuration File Format

### Certificate Authority Configuration
```yaml
caCert:
  serial: <integer>           # Serial number
  validForYears: <integer>    # Validity period in years
  subject:
    country: <string>         # Two-letter country code
    organization: <string>    # Organization name
    organizationalUnit: <string>
    locality: <string>        # City/Locality
    province: <string>        # State/Province
    streetAddress: <string>
    postalCode: <string>
    commonName: <string>      # CA name
```

### End-Entity Certificate Configuration
```yaml
certs:
  <name>:
    serial: <integer>
    validForYears: <integer>
    dnsNames: [<string>]      # List of Subject Alternative Names
    subject:
      # Same fields as CA subject
```

## Security Considerations

1. Key Protection:
   - CA keys should be stored securely
   - Use appropriate file permissions (600 for private keys)
   - Consider using HSMs for production environments

2. Certificate Validity:
   - Keep CA certificates valid longer than end-entity certificates
   - Consider shorter validity periods for production certificates

## Examples

### Creating a Complete PKI for Development

1. Create the configuration:
```yaml
caCert:
  serial: 1
  validForYears: 10
  subject:
    country: US
    organization: Development CA
    commonName: Development Root CA

certs:
  dev.local:
    serial: 1
    validForYears: 1
    dnsNames: ["dev.local", "*.dev.local"]
    subject:
      country: US
      organization: Development
      commonName: dev.local
  
  client:
    serial: 2
    validForYears: 1
    subject:
      country: US
      organization: Development
      commonName: Development Client
```

2. Create the CA:
```bash
./tls create ca
```

3. Create server certificate:
```bash
./tls create cert --name dev.local
```

4. Create client certificate:
```bash
./tls create cert --name client --key-out client.key --cert-out client.crt
```

### Using with Go HTTPS Server

```go
package main

import (
    "crypto/tls"
    "log"
    "net/http"
)

func main() {
    server := &http.Server{
        Addr: ":443",
        TLSConfig: &tls.Config{
            MinVersion: tls.VersionTLS13,
        },
    }
    
    log.Fatal(server.ListenAndServeTLS("server.crt", "server.key"))
}
```

## Acknowledgments

- Built using [Cobra](https://github.com/spf13/cobra) for CLI functionality
- based on Edward Viaene [tls-demo](https://github.com/wardviaene/golang-for-devops-course)
- Inspired by OpenSSL and easy-rsa tools
