package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var recently_used_upload_ids = make(map[string]time.Time)
var ruui_mx sync.Mutex

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
