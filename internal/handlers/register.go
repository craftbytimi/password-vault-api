package handlers

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
)

func RegisterUserHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Please send valid JSON with username and password", http.StatusBadRequest)
		return
	}

	salt := make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		http.Error(w, "Could not generate salt", http.StatusInternalServerError)
		return
	}

	// passwordHash, err := utils.HashPasswordWithSalt(requestData.Password, salt)
	// ...existing code...
	if err != nil {
		http.Error(w, "Could not hash password", http.StatusInternalServerError)
		return
	}

	// ...existing code...

	// Save user to DB or userStore
	// ...existing code...

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully!"))
}
