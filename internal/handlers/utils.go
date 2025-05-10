package handlers

import (
	"encoding/json"
	// "log"
	"net/http"
	"github.com/gosimple/slug"
)

// SlugRequest represents the input for slug generation
type SlugRequest struct {
	Text string `json:"text"`
	Lang string `json:"lang,omitempty"` // Optional language code
}

// SlugResponse represents the slug generation output
type SlugResponse struct {
	Slug string `json:"slug"`
}

// SlugifyHandler handles the API endpoint for generating URL-friendly slugs
// It takes text in any language and returns an ASCII slug using transliteration
func SlugifyHandler(w http.ResponseWriter, r *http.Request) {
	// log.Printf("SlugifyHandler called: %s %s", r.Method, r.URL.Path)

	// Only allow POST
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Method not allowed",
		})
		return
	}

	// Parse request
	var req SlugRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// log.Printf("Error decoding request body: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid request format",
		})
		return
	}

	// log.Printf("Received slugify request for text: '%s', lang: '%s'", req.Text, req.Lang)

	// Generate slug
	var s string
	if req.Lang != "" {
		s = slug.MakeLang(req.Text, req.Lang)
	} else {
		s = slug.Make(req.Text)
	}

	// log.Printf("Generated slug: '%s'", s)

	// Return response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SlugResponse{
		Slug: s,
	})
	// log.Printf("SlugifyHandler completed successfully")
}