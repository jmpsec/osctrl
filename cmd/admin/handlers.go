package main

import (
	"net/http"

	"github.com/javuto/osctrl/pkg/settings"
	"github.com/javuto/osctrl/pkg/utils"
)

// JSONApplication for Content-Type headers
const JSONApplication string = "application/json"

// JSONApplicationUTF8 for Content-Type headers, UTF charset
const JSONApplicationUTF8 string = JSONApplication + "; charset=UTF-8"

// Empty default osquery configuration
const emptyConfiguration string = "data/osquery-empty.conf"

// Handle testing requests
func testingHTTPHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("test"))
}

// Handle error requests
func errorHTTPHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte("oh no..."))
}

// Handler for the favicon
func faviconHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)

	w.Header().Set("Content-Type", "image/png")
	http.ServeFile(w, r, "./static/favicon.png")
}
