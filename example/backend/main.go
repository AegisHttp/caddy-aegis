package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received [%s] %s", r.Method, r.URL.Path)

		w.Header().Set("Content-Type", "application/json")

		response := map[string]interface{}{
			"status":  "success",
			"message": "Hello from Aegis HTTP Backend!",
			"method":  r.Method,
			"path":    r.URL.Path,
			"headers": r.Header,
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding response: %v", err)
		}
	})

	fmt.Println("🚀 Backend server is listening on port 4000")
	if err := http.ListenAndServe(":4000", nil); err != nil {
		log.Fatalf("❌ Server failed: %v", err)
	}
}
