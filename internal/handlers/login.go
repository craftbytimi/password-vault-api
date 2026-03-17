package handlers

import (
	"encoding/json"
	"net/http"
)

func UserLoginHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Please send valid JSON with username and password", http.StatusBadRequest)
		return
	}

	// Fetch user from DB or userStore
	// ...existing code...

	// Verify password
	// ...existing code...

	// Generate JWT token
	// ...existing code...

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful!"))
}
