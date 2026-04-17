package main

import "os"

var STORAGE_PATH = dv(os.Getenv("STORAGE_PATH"), "./data")
var CERT_PATH = os.Getenv("TLS_CERT_PATH")
var KEY_PATH = os.Getenv("TLS_KEY_PATH")
var ADDR = dv(os.Getenv("ADDR"), "6789")
var API_SECRET = os.Getenv("API_SECRET")

// dv returns the default value, `def` if the given `value` is empty.
func dv(value, def string) string {
	if value == "" {
		return def
	}
	return value
}
