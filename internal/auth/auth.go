package auth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
	"wiki-go/internal/config"
	"wiki-go/internal/crypto"
)

// Session represents a user session
type Session struct {
	Username  string
	Role      string  // User role: "admin", "editor", or "viewer"
	CreatedAt time.Time
}

var (
	sessions = make(map[string]Session)
	mu       sync.RWMutex
)

// GenerateSessionToken generates a random session token
func GenerateSessionToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// CreateSession creates a new session for the user
func CreateSession(w http.ResponseWriter, username string, role string, keepLoggedIn bool, cfg *config.Config) error {
	token, err := GenerateSessionToken()
	if err != nil {
		return err
	}

	mu.Lock()
	sessions[token] = Session{
		Username:  username,
		Role:      role,
		CreatedAt: time.Now(),
	}
	mu.Unlock()

	// Set cookie expiration time based on keepLoggedIn flag
	maxAge := 3600 * 24 // 24 hours by default
	if keepLoggedIn {
		maxAge = 3600 * 24 * 30 // 30 days for persistent login
	}

	// Set the secure HTTP-only session token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   !cfg.Server.AllowInsecureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})

	// Set a non-HTTP-only cookie for the username to be accessible by JavaScript
	http.SetCookie(w, &http.Cookie{
		Name:     "session_user",
		Value:    username,
		Path:     "/",
		HttpOnly: false,
		Secure:   !cfg.Server.AllowInsecureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})

	return nil
}

// GetSession retrieves the session for the current request
func GetSession(r *http.Request) *Session {
	c, err := r.Cookie("session_token")
	if err != nil {
		return nil
	}

	mu.RLock()
	session, exists := sessions[c.Value]
	mu.RUnlock()

	if !exists {
		return nil
	}

	// Session expiration is now handled by cookie expiration time
	// which is set in CreateSession based on the keepLoggedIn parameter

	return &session
}

// ClearSession removes the session from the sessions map and clears the cookie
func ClearSession(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	c, err := r.Cookie("session_token")
	if err != nil {
		return
	}

	mu.Lock()
	delete(sessions, c.Value)
	mu.Unlock()

	// Clear the session token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   !cfg.Server.AllowInsecureCookies,
		MaxAge:   -1,
	})

	// Clear the session user cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_user",
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   !cfg.Server.AllowInsecureCookies,
		MaxAge:   -1,
	})
}

// ValidateCredentials validates user credentials against the config
func ValidateCredentials(username, password string, cfg *config.Config) (bool, string) {
	for _, user := range cfg.Users {
		if user.Username == username && crypto.CheckPasswordHash(password, user.Password) {
			// Use the user's role
			role := user.Role
			return true, role
		}
	}
	return false, ""
}

// CheckAuth verifies if the user is authenticated and returns their session
func CheckAuth(r *http.Request) *Session {
	return GetSession(r)
}

// RequireAuth checks if the wiki is private and if the user is authenticated
// Returns true if the user is allowed to access the page
func RequireAuth(r *http.Request, cfg *config.Config) bool {
	// If the wiki is not private, allow access
	if !cfg.Wiki.Private {
		return true
	}

	// If the wiki is private, check if the user is authenticated
	session := GetSession(r)
	return session != nil
}

// RequireRole checks if user has required role or higher
func RequireRole(r *http.Request, requiredRole string) bool {
	session := GetSession(r)
	if session == nil {
		return false
	}

	// Role hierarchy: admin > editor > viewer
	switch requiredRole {
	case "admin":
		return session.Role == "admin"
	case "editor":
		return session.Role == "admin" || session.Role == "editor"
	case "viewer":
		return session.Role == "admin" || session.Role == "editor" || session.Role == "viewer"
	default:
		return false
	}
}
