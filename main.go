package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"

	"github.com/tiredkangaroo/storage/storage"
)

const FILE_SIZE_LIMIT = 5 << 20 // 50 MB

func main() {
	var store storage.Storage
	var err error

	store, err = storage.NewFileStorage(dv(os.Getenv("STORAGE_PATH"), "./data"))
	if err != nil {
		slog.Error("init storage", "error", err)
		return
	}

	http.HandleFunc("POST /push", func(w http.ResponseWriter, r *http.Request) {
		// generate a random key with appropriate file extension (if possible)
		key := random()
		mimeType := r.Header.Get("Content-Type")
		exts, err := mime.ExtensionsByType(mimeType)
		if err == nil && len(exts) > 0 {
			key += exts[0] // add the first extension
		}

		// read with the limited size request body
		if r.ContentLength > FILE_SIZE_LIMIT {
			http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
			return
		}
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

	cert_path := os.Getenv("TLS_CERT_PATH")
	key_path := os.Getenv("TLS_KEY_PATH")

	if cert_path != "" && key_path != "" {
		slog.Info("server", "msg", "starting HTTPS server", "addr", dv(os.Getenv("ADDR"), "6789"))
		if err := http.ListenAndServeTLS(dv(os.Getenv("ADDR"), "6789"), cert_path, key_path, nil); err != nil {
			slog.Error("server", "error", err)
		}
	} else {
		slog.Info("server", "msg", "starting HTTP server", "addr", dv(os.Getenv("ADDR"), "6789"))
		if err := http.ListenAndServe(dv(os.Getenv("ADDR"), "6789"), nil); err != nil {
			slog.Error("server", "error", err)
		}
	}
}

func dv(value, def string) string {
	if value == "" {
		return def
	}
	return value
}

func random() string {
	var r [16]byte
	rand.Read(r[:])
	return fmt.Sprintf("%x", r[:])
}
