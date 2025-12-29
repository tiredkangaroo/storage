package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/tiredkangaroo/storage/storage"
)

const FILE_SIZE_LIMIT = 5 << 20 // 50 MB
var STORAGE_PATH = dv(os.Getenv("STORAGE_PATH"), "./data")
var CERT_PATH = os.Getenv("TLS_CERT_PATH")
var KEY_PATH = os.Getenv("TLS_KEY_PATH")
var ADDR = dv(os.Getenv("ADDR"), "6789")
var API_SECRET = os.Getenv("API_SECRET")

var recently_used_upload_ids = make(map[string]time.Time)
var ruui_mx sync.Mutex

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

	http.HandleFunc("POST /push", func(w http.ResponseWriter, r *http.Request) {
		// check api secret
		if err := checkAuth(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			slog.Warn("auth", "msg", "unauthorized upload attempt", "error", err)
			return
		}

		// generate a random key with appropriate file extension (if possible)
		key := random()
		mimeType := r.Header.Get("Content-Type")
		exts, err := mime.ExtensionsByType(mimeType)
		if err == nil && len(exts) > 0 {
			key += exts[0] // add the first extension
		}

		// reject if content length exceeds limit -- clients can lie about this but it's a good hot path
		// for large uploads made in good faith or dumb attackers
		if r.ContentLength > FILE_SIZE_LIMIT {
			http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
			return
		}
		// read with the limited size request body
		r.Body = http.MaxBytesReader(w, r.Body, FILE_SIZE_LIMIT)
		defer r.Body.Close()

		// save the file to storage
		if err := store.Save(key, r.Body); err != nil {
			http.Error(w, fmt.Sprintf("an error occured (key: %v)", err), http.StatusInternalServerError)
			slog.Error("save file", "key", key, "error", err)
			return
		}

		// respond with the generated key
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(key))
	})

	// pull is left intentionally unsecured for public access
	http.HandleFunc("GET /pull/{key}", func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("key") // get key from path

		rc, err := store.Load(key) // load the file from storage
		if err == storage.ErrKeyNotFound {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(w, "an error occured", http.StatusInternalServerError)
			slog.Error("load file", "key", key, "error", err)
			return
		}
		defer rc.Close()

		w.WriteHeader(http.StatusOK)                                            // write OK status
		w.Header().Set("Content-Type", mime.TypeByExtension(filepath.Ext(key))) // set content type based on file extension
		if _, err := io.Copy(w, rc); err != nil {                               // write the file to response
			http.Error(w, "an error occured", http.StatusInternalServerError)
			slog.Error("write file to response", "key", key, "error", err)
			return
		}
	})

	http.HandleFunc("DELETE /delete/{key}", func(w http.ResponseWriter, r *http.Request) {
		if err := checkAuth(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			slog.Warn("auth", "msg", "unauthorized delete attempt", "error", err)
			return
		}
		key := r.PathValue("key") // get key from path

		if err := store.Delete(key); err == storage.ErrKeyNotFound {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(w, "an error occured", http.StatusInternalServerError)
			slog.Error("delete file", "key", key, "error", err)
			return
		}

		w.WriteHeader(http.StatusNoContent) // respond with no content status
	})

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

// dv returns the default value, `def` if the given `value` is empty.
func dv(value, def string) string {
	if value == "" {
		return def
	}
	return value
}

// random generates a random 32 character hexadecimal string.
func random() string {
	var r [16]byte
	rand.Read(r[:])
	return fmt.Sprintf("%x", r[:])
}

func checkAuth(r *http.Request) error {
	if API_SECRET == "" {
		return nil // no auth required
	}
	timestamp := r.Header.Get("X-Timestamp")
	signature := r.Header.Get("X-Signature")
	uploadID := r.Header.Get("X-Upload-ID")

	// check required headers are present
	if timestamp == "" || signature == "" || uploadID == "" {
		return fmt.Errorf("missing auth headers")
	}
	if len(uploadID) > 48 {
		return fmt.Errorf("upload id too large")
	}

	// make sure timestamp is recent (+/- 10 seconds)
	now := time.Now().Unix()
	providedTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || math.Abs(float64(now-providedTimestamp)) > 10 {
		return fmt.Errorf("invalid timestamp")
	}

	// check upload ID hasn't been used recently
	ruui_mx.Lock()
	defer ruui_mx.Unlock()
	if _, ok := recently_used_upload_ids[uploadID]; ok {
		return fmt.Errorf("nah no way u rly thought a replay attack would work smh 🤦‍♂️💔")
	}

	// canoncical string: uploadID + \n + timestamp
	cs := uploadID + "\n" + timestamp
	csh := hmac.New(sha256.New, []byte(API_SECRET))
	csh.Write([]byte(cs))
	csb := csh.Sum(nil)
	csb_hex := fmt.Sprintf("%x", csb)

	// compare signatures
	if !hmac.Equal([]byte(csb_hex), []byte(signature)) {
		return fmt.Errorf("invalid signature")
	}

	// mark upload ID as used
	recently_used_upload_ids[uploadID] = time.Now()
	return nil
}

func cleanupUploadIDs() {
	// remove upload IDs older than 1 minute
	ruui_mx.Lock()
	defer ruui_mx.Unlock()

	for id, t := range recently_used_upload_ids {
		if time.Since(t) > time.Minute {
			delete(recently_used_upload_ids, id)
		}
	}
}

func startCleanupRoutine() {
	go func() {
		for range time.Tick(time.Second * 30) {
			cleanupUploadIDs()
		}
	}()
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
