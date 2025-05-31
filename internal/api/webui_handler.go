package api

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"path" // For path.Join, though not strictly needed with http.FS serving index.html
	"strings"
)

//go:embed all:../../web/ui
var embeddedWebUI embed.FS // Embeds the web/ui directory

// RegisterWebUIHandlers sets up the routing for the WebUI.
func RegisterWebUIHandlers(mux *http.ServeMux) {
	// Create a sub-filesystem to serve files from the "web/ui" directory
	// within the embedded filesystem. This makes paths relative to "web/ui".
	uiFS, err := fs.Sub(embeddedWebUI, "web/ui")
	if err != nil {
		log.Fatalf("Failed to create sub FS for web UI: %v", err)
	}

	// File server for the UI assets, serving from the root of the sub-filesystem
	fileServer := http.FileServer(http.FS(uiFS))

	// Handler for /webui/ (and its subpaths)
	mux.HandleFunc("/webui/", func(w http.ResponseWriter, r *http.Request) {
		// Strip the /webui/ prefix so http.FileServer gets paths relative to uiFS root
		// e.g., /webui/style.css becomes /style.css for the fileServer
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/webui")
		// If path becomes empty (was /webui/), serve index.html from root of uiFS
		// http.FileServer with http.FS automatically serves index.html for "/"
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})

	// Redirect /webui (without trailing slash) to /webui/
	// This ensures that relative paths in index.html (if any) work correctly
	// and that the main handler for /webui/ is always hit.
	mux.HandleFunc("/webui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/webui/", http.StatusMovedPermanently)
	})
}
