package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"service":   "Aether Dummy Backend",
		"status":    "received",
		"method":    r.Method,
		"path":      r.URL.Path,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	_ = json.NewEncoder(w).Encode(response)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	log.Println("Dummy backend listening on http://localhost:9090")

	if err := http.ListenAndServe("127.0.0.1:9090", mux); err != nil {
		log.Fatal(err)
	}
}
