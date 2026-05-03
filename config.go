package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	// storage
	Storage struct {
		Type string `json:"type"` // "local" or "s3"
		// local
		Path string `json:"path"` // for local storage, the directory to store files in
		// s3
		BaseEndpoint    string `json:"base_endpoint"` // for cf it's https://[account_id].r2.cloudflarestorage.com
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	} `json:"storage"`

	// optional tls config for https
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`

	// server info
	PublicURL string `json:"public_url"`
	Addr      string `json:"addr"`

	// whether to enable the hc cdn endpoints (note: api secret is sent directly, there isn't a signature or anything)
	EnableMockCDNEndpoints bool `json:"enable_mock_cdn_endpoints"`

	APISecret string `json:"api_secret"`
}

var DefaultConfig Config
var CONFIG_FILE_PATH = os.Getenv("CONFIG_FILE_PATH")

func initConfig() error {
	cfPath := CONFIG_FILE_PATH
	if cfPath == "" {
		cfPath = "config.json"
	}

	cfg, err := os.ReadFile(CONFIG_FILE_PATH)
	if err != nil {
		return fmt.Errorf("read config file at %s: %w", cfPath, err)
	}

	if err := json.Unmarshal(cfg, &DefaultConfig); err != nil {
		return fmt.Errorf("unmarshal config file: %w", err)
	}
	return nil
}
