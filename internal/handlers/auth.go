package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/craftbytimi/password-vault-api/internal/models"
)

// userStore is a simple map that stores users in memory.
// This is just for learning. In real apps, use a database.
var userStore = make(map[string]models.User)

// RegisterHandler is a function that lets users sign up.
// It reads the username and password from the request, hashes the password, and saves the user.
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Step 1: Make a struct to hold the incoming data
	var requestData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Step 2: Read the JSON from the request body into requestData
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		// If the data is not valid JSON, send an error response
		http.Error(w, "Please send valid JSON with username and password", http.StatusBadRequest)
		return
	}

	// Step 3: Make a new user with the username
	user := models.User{Username: requestData.Username}

	// Step 4: Hash the password and store it in the user
	err = user.SetPassword(requestData.Password)
	if err != nil {
		// If hashing fails, send an error response
		http.Error(w, "Could not set password", http.StatusInternalServerError)
		return
	}

	// Step 5: Save the user in the userStore map
	userStore[requestData.Username] = user

	// Step 6: Send a success response
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully!"))
}
