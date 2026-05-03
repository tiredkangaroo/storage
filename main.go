package main

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tiredkangaroo/storage/storage"
)

const FILE_SIZE_LIMIT = 100 << 20 // 100 MB

func main() {
	if err := initConfig(); err != nil {
		slog.Error("init config", "error", err)
		return
	}

	if DefaultConfig.APISecret != "" {
		slog.Info("auth", "msg", "API secret set, authentication enabled")
		startCleanupRoutine() // start the cleanup routine for upload IDs
	} else {
		slog.Warn("auth", "msg", "API secret not set, authentication disabled")
	}

	var store storage.Storage
	var err error

	store, err = storage.NewFileStorage(DefaultConfig.Storage.Path)
	if err != nil {
		slog.Error("init storage", "error", err)
		return
	}

	http.HandleFunc("POST /push", CreatePushHandler(store))

	// pull is left intentionally unsecured for public access
	http.HandleFunc("GET /pull/{key}", CreatePullHandler(store))

	http.HandleFunc("POST /api/v4/upload", CreateHCCDNPushHandler(store))                 // hc cdn endpoint
	http.HandleFunc("POST /api/v4/upload_from_url", CreateHCCDNPushFromURLHandler(store)) // another hc cdn endpoint
	http.HandleFunc("DELETE /delete/{key}", CreateDeleteHandler(store))

	if DefaultConfig.CertPath != "" && DefaultConfig.KeyPath != "" {
		slog.Info("server", "msg", "starting HTTPS server", "addr", DefaultConfig.Addr)
		if err := http.ListenAndServeTLS(DefaultConfig.Addr, DefaultConfig.CertPath, DefaultConfig.KeyPath, nil); err != nil {
			slog.Error("server", "error", err)
		}
	} else {
		slog.Info("server", "msg", "starting HTTP server", "addr", DefaultConfig.Addr)
		if err := http.ListenAndServe(DefaultConfig.Addr, nil); err != nil {
			slog.Error("server", "error", err)
		}
	}
}

// random generates a random 32 character hexadecimal string.
func random() string {
	var r [16]byte
	rand.Read(r[:])
	return fmt.Sprintf("%x", r[:])
}
