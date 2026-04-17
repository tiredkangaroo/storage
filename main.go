package main

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tiredkangaroo/storage/storage"
)

const FILE_SIZE_LIMIT = 5 << 20 // 50 MB

func main() {
	if API_SECRET != "" {
		slog.Info("auth", "msg", "API secret set, authentication enabled")
		startCleanupRoutine() // start the cleanup routine for upload IDs
	} else {
		slog.Warn("auth", "msg", "API secret not set, authentication disabled")
	}

	var store storage.Storage
	var err error

	store, err = storage.NewFileStorage(STORAGE_PATH)
	if err != nil {
		slog.Error("init storage", "error", err)
		return
	}

	http.HandleFunc("POST /push", CreatePushHandler(store))

	// pull is left intentionally unsecured for public access
	http.HandleFunc("GET /pull/{key}", CreatePullHandler(store))

	http.HandleFunc("DELETE /delete/{key}", CreateDeleteHandler(store))

	if CERT_PATH != "" && KEY_PATH != "" {
		slog.Info("server", "msg", "starting HTTPS server", "addr", ADDR)
		if err := http.ListenAndServeTLS(ADDR, CERT_PATH, KEY_PATH, nil); err != nil {
			slog.Error("server", "error", err)
		}
	} else {
		slog.Info("server", "msg", "starting HTTP server", "addr", ADDR)
		if err := http.ListenAndServe(ADDR, nil); err != nil {
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

// example code to auth
// API_SECRET is the shared secret between client and server
// func signRequest(req *http.Request) {
// 	uploadID := uuid.New().String()
// 	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)

// 	// canoncical string: uploadID + \n + timestamp
// 	cs := uploadID + "\n" + timestamp
// 	csh := hmac.New(sha256.New, []byte(API_SECRET))
// 	csh.Write([]byte(cs))
// 	csb := csh.Sum(nil)
// 	csb_hex := fmt.Sprintf("%x", csb)

// 	req.Header.Set("X-Upload-ID", uploadID)
// 	req.Header.Set("X-Timestamp", timestamp)
// 	req.Header.Set("X-Signature", csb_hex)
// }
