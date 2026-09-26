package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("[BACKEND] Securely received request: %s\n", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success", "message":"Protected data accessed"}`))
	})

	fmt.Println("Dummy backend listening on localhost:9090")
	http.ListenAndServe(":9090", nil)
}
