package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	// Proxy requests from /api/ to Caddy (Port 3003)
	caddyURL, err := url.Parse("http://localhost:3003")
	if err != nil {
		log.Fatalf("❌ Failed to parse Caddy URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(caddyURL)

	http.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Proxying request to Caddy %s", r.URL.Path)
		proxy.ServeHTTP(w, r)
	})

	// Serve the static frontend files (index.html)
	fs := http.FileServer(http.Dir("."))
	http.Handle("/", fs)

	fmt.Println("🌐 Frontend server is running at http://localhost:5173")
	if err := http.ListenAndServe(":5173", nil); err != nil {
		log.Fatalf("❌ Frontend server failed: %v", err)
	}
}
