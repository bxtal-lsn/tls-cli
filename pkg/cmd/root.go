package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/wardviaene/golang-for-devops-course/tls-demo/pkg/cert"
	"gopkg.in/yaml.v2"
)

type Config struct {
	CACert *cert.CACert          `yaml:"caCert"`
	Cert   map[string]*cert.Cert `yaml:"certs"`
}

type CertError struct {
	Operation string
	Err       error
}

func (e *CertError) Error() string {
	return fmt.Sprintf("%s failed: %v", e.Operation, e.Err)
}

type ConfigError struct {
	Stage string
	Path  string
	Err   error
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("configuration %s failed for %s: %v", e.Stage, e.Path, e.Err)
}

var (
	cfgFilePath string
	config      Config
)

var rootCmd = &cobra.Command{
	Use:   "tls",
	Short: "tls is a command line tool for TLS.",
	Long: `tls is a command line tool for TLS.
		Mainly used for generation of X.509 certificates, but can be extended`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVarP(&cfgFilePath, "config", "c", "", "config file (default is tls.yaml)")
}

func (c *Config) validate() error {
	if c.CACert == nil {
		return &ConfigError{
			Stage: "validation",
			Path:  cfgFilePath,
			Err:   fmt.Errorf("CA certificate configuration is missing"),
		}
	}

	if len(c.Cert) == 0 {
		return &ConfigError{
			Stage: "validation",
			Path:  cfgFilePath,
			Err:   fmt.Errorf("no certificates configured"),
		}
	}

	return nil
}

func loadConfigFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, &ConfigError{
				Stage: "path resolution",
				Path:  path,
				Err:   err,
			}
		}
		path = absPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &ConfigError{
			Stage: "reading",
			Path:  path,
			Err:   err,
		}
	}

	return data, nil
}

func initConfig() {
	if cfgFilePath == "" {
		cfgFilePath = "tls.yaml"
	}

	cfgFileBytes, err := loadConfigFile(cfgFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if err := yaml.Unmarshal(cfgFileBytes, &config); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse config: %v\n",
			&ConfigError{
				Stage: "parsing",
				Path:  cfgFilePath,
				Err:   err,
			})
		os.Exit(1)
	}

	if err := config.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %v\n", err)
		os.Exit(1)
	}
}

