package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"wiki-go/internal/crypto"
	"wiki-go/internal/roles"

	"gopkg.in/yaml.v3"
)

// ConfigFilePath defines the global path to the configuration file
const ConfigFilePath = "data/config.yaml"

// User represents a user with authentication credentials
type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Role     string `yaml:"role"`     // "admin", "editor", or "viewer"
}

// Role constants - using the ones defined in roles package
var (
	RoleAdmin  = roles.RoleAdmin  // Can do anything
	RoleEditor = roles.RoleEditor // Can edit documents and post comments
	RoleViewer = roles.RoleViewer // Can only view documents and post comments
)

// Config represents the server configuration
type Config struct {
	Server struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
		// When set to true, allows cookies to be sent over non-HTTPS connections.
		// WARNING: Only enable this in trusted environments like a homelab
		// where HTTPS is not available. This reduces security by allowing
		// cookies to be transmitted in plain text.
		AllowInsecureCookies bool `yaml:"allow_insecure_cookies"`
		// Enable native TLS. When true, application will run over HTTPS using the
		// supplied certificate and key paths.
		SSL      bool   `yaml:"ssl"`
		SSLCert  string `yaml:"ssl_cert"`
		SSLKey   string `yaml:"ssl_key"`
	} `yaml:"server"`
	Wiki struct {
		RootDir                   string `yaml:"root_dir"`
		DocumentsDir              string `yaml:"documents_dir"`
		Title                     string `yaml:"title"`
		Owner                     string `yaml:"owner"`
		Notice                    string `yaml:"notice"`
		Timezone                  string `yaml:"timezone"`
		Private                   bool   `yaml:"private"`
		DisableComments           bool   `yaml:"disable_comments"` // Disable comments system-wide when true
		DisableFileUploadChecking bool   `yaml:"disable_file_upload_checking"` // Disable mimetype checking for file uploads when true
		MaxVersions               int    `yaml:"max_versions"`
		MaxUploadSize             int    `yaml:"max_upload_size"` // Maximum upload file size in MB
		Language                  string `yaml:"language"`        // Default language for the wiki
	} `yaml:"wiki"`
	Users []User `yaml:"users"`
}

// LoadConfig loads the configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	// Set default values
	config := &Config{}
	config.Server.Host = "0.0.0.0" // Set to localhost for local development
	config.Server.Port = 8080
	config.Server.AllowInsecureCookies = false // Default to secure cookies
	config.Server.SSL = false
	config.Server.SSLCert = ""
	config.Server.SSLKey = ""
	config.Wiki.RootDir = "data"
	config.Wiki.DocumentsDir = "documents"
	config.Wiki.Title = "📚 Wiki-Go"
	config.Wiki.Owner = "wiki.example.com"
	config.Wiki.Notice = "Copyright 2025 © All rights reserved."
	config.Wiki.Timezone = "America/Vancouver"
	config.Wiki.Private = false
	config.Wiki.DisableComments = false
	config.Wiki.DisableFileUploadChecking = false // Default to false - always check file uploads
	config.Wiki.MaxVersions = 10   // Default value
	config.Wiki.MaxUploadSize = 10 // Default value
	config.Wiki.Language = "en"    // Default to English
	config.Users = []User{}        // Initialize empty users array

	// Read config file
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Ensure the directory exists
			dir := filepath.Dir(path)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
			}

			// Hash the default admin password
			hashedPassword, err := crypto.HashPassword("admin")
			if err != nil {
				return nil, err
			}

			// Add default admin user
			config.Users = append(config.Users, User{
				Username: "admin",
				Password: hashedPassword,
				Role:     RoleAdmin,
			})

			// Format all users
			var usersStr strings.Builder
			for _, user := range config.Users {
				if usersStr.Len() > 0 {
					usersStr.WriteString("\n")
				}
				usersStr.WriteString(FormatUserEntry(user))
			}

			// Fill in the template with values from the config
			configData := fmt.Sprintf(
				GetConfigTemplate(),
				config.Server.Host,
				config.Server.Port,
				config.Server.AllowInsecureCookies,
				config.Server.SSL,
				config.Server.SSLCert,
				config.Server.SSLKey,
				config.Wiki.RootDir,
				config.Wiki.DocumentsDir,
				config.Wiki.Title,
				config.Wiki.Owner,
				config.Wiki.Notice,
				config.Wiki.Timezone,
				config.Wiki.Private,
				config.Wiki.DisableComments,
				config.Wiki.DisableFileUploadChecking,
				config.Wiki.MaxVersions,
				config.Wiki.MaxUploadSize,
				config.Wiki.Language,
				usersStr.String(),
			)

			// Write the config file
			err = os.WriteFile(path, []byte(configData), 0644)
			if err != nil {
				return nil, err
			}
			return config, nil
		}
		return nil, err
	}

	// Parse YAML
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	// Migrate user roles from is_admin to role - this is now done in main.go

	return config, nil
}

// GetConfigTemplate returns the template for the config file with comments
func GetConfigTemplate() string {
	return `server:
    host: %s
    port: %d
    # When set to true, allows cookies to be sent over non-HTTPS connections.
    # WARNING: Only enable this in trusted environments like a homelab
    # where HTTPS is not available. This reduces security by allowing
    # cookies to be transmitted in plain text.
    allow_insecure_cookies: %t
    # Enable native TLS. When true, application will run over HTTPS using the
    # supplied certificate and key paths.
    ssl: %t
    ssl_cert: %s
    ssl_key: %s
wiki:
    root_dir: %s
    documents_dir: %s
    title: "%s"
    owner: %s
    notice: %s
    timezone: %s
    private: %t
    disable_comments: %t
    disable_file_upload_checking: %t
    max_versions: %d
    # Maximum file upload size in MB
    max_upload_size: %d
    # Default language for the wiki interface (en, es, etc.)
    language: %s
users:
%s`
}

// FormatUserEntry formats a single user entry for the config file
func FormatUserEntry(user User) string {
	return fmt.Sprintf("    - username: %s\n      password: %s\n      role: %s",
		user.Username, user.Password, user.Role)
}

// SaveConfig saves the configuration to a writer
func SaveConfig(cfg *Config, w io.Writer) error {
	// Format all users
	var usersStr strings.Builder
	for _, user := range cfg.Users {
		if usersStr.Len() > 0 {
			usersStr.WriteString("\n")
		}
		usersStr.WriteString(FormatUserEntry(user))
	}

	// Fill in the template with values from the config
	configData := fmt.Sprintf(
		GetConfigTemplate(),
		cfg.Server.Host,
		cfg.Server.Port,
		cfg.Server.AllowInsecureCookies,
		cfg.Server.SSL,
		cfg.Server.SSLCert,
		cfg.Server.SSLKey,
		cfg.Wiki.RootDir,
		cfg.Wiki.DocumentsDir,
		cfg.Wiki.Title,
		cfg.Wiki.Owner,
		cfg.Wiki.Notice,
		cfg.Wiki.Timezone,
		cfg.Wiki.Private,
		cfg.Wiki.DisableComments,
		cfg.Wiki.DisableFileUploadChecking,
		cfg.Wiki.MaxVersions,
		cfg.Wiki.MaxUploadSize,
		cfg.Wiki.Language,
		usersStr.String(),
	)

	_, err := w.Write([]byte(configData))
	return err
}
