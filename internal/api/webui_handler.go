package api

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"strings"
)

//go:embed all:static_web_ui
var embeddedStaticContentRoot embed.FS

func RegisterWebUIHandlers(mux *http.ServeMux) {
	actualUI_FS, err := fs.Sub(embeddedStaticContentRoot, "static_web_ui")
	if err != nil {
		log.Fatalf("Failed to create sub FS for 'static_web_ui': %v. Ensure 'internal/api/static_web_ui' exists.", err)
	}
	fileServer := http.FileServer(http.FS(actualUI_FS))
	mux.HandleFunc("/webui/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/webui/")
		if p == "" {
			p = "/"
		}
		r.URL.Path = p
		fileServer.ServeHTTP(w, r)
	})
	mux.HandleFunc("/webui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/webui/", http.StatusMovedPermanently)
	})
}