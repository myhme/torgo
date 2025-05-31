package api

import (
	"embed"
	"io/fs" // Required for fs.Sub
	"log"
	"net/http"
	"strings"
)

// Embed the 'static_web_ui' directory, which is now a subdirectory of this 'api' package.
// This assumes your project structure has been updated to:
// torgo/internal/api/static_web_ui/index.html (and other assets)
//
// The 'all:' prefix can be used if you need to embed files that might otherwise be ignored
// (like dotfiles), but for typical web assets (html, css, js), it's often not strictly necessary.
// If you use 'all:static_web_ui', then embeddedStaticContent will contain 'static_web_ui' as a root entry.
// If you use just 'static_web_ui', it embeds the *contents* of 'static_web_ui'.
// Let's use 'all:' for explicitness, meaning we'll need fs.Sub.
//go:embed all:static_web_ui
var embeddedStaticContentRoot embed.FS

// RegisterWebUIHandlers sets up the routing for the WebUI.
func RegisterWebUIHandlers(mux *http.ServeMux) {
	// Since we used "all:static_web_ui", embeddedStaticContentRoot contains "static_web_ui"
	// as a directory at its root. We need to create a sub-filesystem to serve from *within* it.
	actualUI_FS, err := fs.Sub(embeddedStaticContentRoot, "static_web_ui")
	if err != nil {
		log.Fatalf("Failed to create sub FS for 'static_web_ui' from embedded content: %v. Ensure 'internal/api/static_web_ui' exists and contains files.", err)
	}

	fileServer := http.FileServer(http.FS(actualUI_FS))

	mux.HandleFunc("/webui/", func(w http.ResponseWriter, r *http.Request) {
		// Strip the /webui/ prefix.
		// e.g., if URL is /webui/style.css, p becomes "style.css"
		// e.g., if URL is /webui/, p becomes ""
		p := strings.TrimPrefix(r.URL.Path, "/webui/")

		// If the path after stripping is empty (it was exactly "/webui/"),
		// http.FileServer, when serving an fs.FS, will look for "index.html"
		// at the root of that fs.FS (which is actualUI_FS here).
		// So, if p is "", it effectively serves "index.html".
		// If you need to be explicit or if the path might be just "/":
		if p == "" {
			p = "/" // This ensures index.html is served from the root of actualUI_FS
		}
		
		r.URL.Path = p // Update the request path for the file server
		fileServer.ServeHTTP(w, r)
	})

	// Redirect /webui (without trailing slash) to /webui/
	mux.HandleFunc("/webui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/webui/", http.StatusMovedPermanently)
	})
}
