package common

import (
	"encoding/json"
	"net/http"
)

// JSONResponse is a helper function to write JSON responses
func JSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
