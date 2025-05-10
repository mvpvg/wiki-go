package handlers

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"wiki-go/internal/auth"
	"wiki-go/internal/config"
	"wiki-go/internal/crypto"
	"wiki-go/internal/resources"
	"wiki-go/internal/i18n"
	"wiki-go/internal/roles"
)

type LoginRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	KeepLoggedIn bool   `json:"keepLoggedIn"`
}

// LoginHandler handles API login requests
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Method not allowed",
		})
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid request body",
		})
		return
	}

	// Validate credentials
	valid, role := auth.ValidateCredentials(req.Username, req.Password, cfg)
	if !valid {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid credentials",
		})
		return
	}

	// Create session
	if err := auth.CreateSession(w, req.Username, role, req.KeepLoggedIn, cfg); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Failed to create session",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Login successful",
	})
}

// CheckAuthHandler checks if the user is authenticated
func CheckAuthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	session := auth.GetSession(r)
	if session == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
		return
	}

	// Return user information including role
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"username": session.Username,
		"role":     session.Role,
	})
}

// LogoutHandler handles user logout
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	auth.ClearSession(w, r, cfg)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Logout successful",
	})
}

// LoginPageHandler renders the login page
func LoginPageHandler(w http.ResponseWriter, r *http.Request) {
	// If user is already logged in, redirect to home page
	session := auth.GetSession(r)
	if session != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Prepare the data for the template
	data := struct {
		Config *config.Config
		Theme  string
	}{
		Config: cfg,
		Theme:  "light", // Default theme
	}

	// Get theme from cookie if available
	if cookie, err := r.Cookie("theme"); err == nil {
		data.Theme = cookie.Value
	}

	// Create function map with translation function
	funcMap := template.FuncMap{
		"t": func(key string) string {
			return i18n.Translate(key)
		},
	}

	// Get and execute login template with translation function
	tmpl, err := template.New("login.html").Funcs(funcMap).ParseFS(resources.GetTemplatesFS(), "templates/login.html")
	if err != nil {
		http.Error(w, "Error loading login template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set content type header before writing response
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Execute template directly to response writer
	err = tmpl.Execute(w, data)
	if err != nil {
		// Since we've already started writing the response, we can't use http.Error here
		// But we can log the error
		log.Printf("Error rendering login template: %v", err)
	}
}

// CheckDefaultPasswordHandler checks if the default admin password is still in use
func CheckDefaultPasswordHandler(w http.ResponseWriter, r *http.Request) {
	// Default admin credentials (typically admin/admin)
	defaultUsername := "admin"
	defaultPassword := "admin"

	// Check if any admin user still has the default password
	defaultPasswordInUse := false

	for _, user := range cfg.Users {
		if user.Role == roles.RoleAdmin && user.Username == defaultUsername {
			// Check if password is still the default
			if crypto.CheckPasswordHash(defaultPassword, user.Password) {
				defaultPasswordInUse = true
				break
			}
		}
	}

	// Return the result
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"defaultPasswordInUse": defaultPasswordInUse,
	})
}
