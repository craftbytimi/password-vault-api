package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/craftbytimi/password-vault-api/internal/models"
	"github.com/craftbytimi/password-vault-api/internal/utils"
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

func LoginHandler(w http.ResponseWriter, r *http.Request) {
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

	// Step 3: Look up the user in the userStore map
	user, exists := userStore[requestData.Username]
	if !exists {
		// If the user does not exist, send an error response
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Step 4: Check if the provided password matches the stored hashed password
	ok := utils.ComparePasswordHash(requestData.Password, user.HashedPassword)
	if !ok {
		// If the password does not match, send an error response
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := utils.GenerateJWT(user.Username)
	if err != nil {
		http.Error(w, "Could not generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
	// Step 5: If the login is successful, send a success response
	w.Write([]byte("Login successful!"))
}

func ValidatePasswordHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Please send valid JSON with a password", http.StatusBadRequest)
		return
	}

	err = utils.ValidatePassword(requestData.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Write([]byte("Password is valid!"))

	// validate jwt token from Authorization header
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}
	// Here you would typically call a function to validate the JWT token
	err = utils.ValidateJWT(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	w.Write([]byte("Token is valid!"))
}
