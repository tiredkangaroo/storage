package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"path/filepath"
	"time"

	"github.com/tiredkangaroo/storage/storage"
)

// post /push handler:
// header:
// - content-type
// - additional authentication headers if API_SECRET is set
func CreatePushHandler(store storage.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
	}
}

// imitates hc cdn /api/v4/upload endpoint
// the pull url patterns will not be the same as the hc cdn ones (/uuid/filename)
func CreateHCCDNPushHandler(store storage.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// check api secret
		if err := checkAuth(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			slog.Warn("auth", "msg", "unauthorized upload attempt", "error", err)
			return
		}

		// generate a random key with appropriate file extension (if possible)
		key := random()

		// reject if content length exceeds limit -- clients can lie about this but it's a good hot path
		// for large uploads made in good faith or dumb attackers
		if r.ContentLength > FILE_SIZE_LIMIT {
			http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
			return
		}

		// read from multipart form data, the file should be in the `file` field
		if err := r.ParseMultipartForm(FILE_SIZE_LIMIT); err != nil {
			http.Error(w, "invalid multipart form data or size exceeded", http.StatusBadRequest)
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "invalid multipart form data", http.StatusBadRequest)
			return
		}
		defer file.Close()
		mimeType := header.Header.Get("Content-Type")
		exts, err := mime.ExtensionsByType(mimeType)
		if err == nil && len(exts) > 0 {
			key += exts[0] // add the first extension
		}

		// save the file to storage
		if err := store.Save(key, file); err != nil {
			http.Error(w, fmt.Sprintf("an error occured (key: %v)", err), http.StatusInternalServerError)
			slog.Error("save file", "key", key, "error", err)
			return
		}

		// respond with the generated key
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"id":           key,
			"filename":     header.Filename,
			"size":         header.Size,
			"content_type": header.Header.Get("Content-Type"),
			"url":          PUBLIC_URL + "/pull/" + key,
			"created_at":   time.Now().Format(time.RFC3339),
		}) // that's the hc cdn response format
	}
}

// does not support X-Download-Authorization header that hc cdn does
func CreateHCCDNPushFromURLHandler(store storage.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// check api secret
		if err := checkAuth(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			slog.Warn("auth", "msg", "unauthorized upload attempt", "error", err)
			return
		}

		// generate a random key with appropriate file extension (if possible)
		key := random()

		// read url from json body
		var body struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json body", http.StatusBadRequest)
			return
		}

		// download the file from the url
		resp, err := http.Get(body.URL)
		if err != nil || resp.StatusCode != http.StatusOK {
			http.Error(w, "failed to download file from url", http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()

		mimeType := resp.Header.Get("Content-Type")
		exts, err := mime.ExtensionsByType(mimeType)
		if err == nil && len(exts) > 0 {
			key += exts[0] // add the first extension
		}

		// this relies on the server providing a content length header (and it not lying) but it's better than nothing
		if resp.ContentLength > FILE_SIZE_LIMIT {
			http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
			return
		}

		// save the file to storage
		rd := io.LimitReader(resp.Body, FILE_SIZE_LIMIT) // limit the size of the downloaded file
		if err := store.Save(key, rd); err != nil {
			http.Error(w, fmt.Sprintf("an error occured (key: %v)", err), http.StatusInternalServerError)
			slog.Error("save file", "key", key, "error", err)
			return
		}

		// respond with the same hc cdn json
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"id":           key,
			"filename":     filepath.Base(body.URL), // idk if that works but let's see :hmm:
			"size":         resp.ContentLength,
			"content_type": mimeType,
			"url":          PUBLIC_URL + "/pull/" + key,
			"created_at":   time.Now().Format(time.RFC3339),
		})
	}
}

func CreatePullHandler(store storage.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
	}
}

func CreateDeleteHandler(store storage.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
	}
}
