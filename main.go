package main

import (
	"fmt"
	"log"
	"net/http"

	"wiki-go/internal/config"
	"wiki-go/internal/handlers"
	"wiki-go/internal/migration"
	"wiki-go/internal/routes"
	"wiki-go/internal/static"

	// Import goldext package for its initialization side effects
	_ "wiki-go/internal/goldext"
)

func main() {
	// Migrate user roles from old IsAdmin to new role-based system
	if err := migration.MigrateUserRoles(config.ConfigFilePath); err != nil {
		log.Fatal("Error migrating user roles:", err)
	}

	// Load configuration (after migration)
	cfg, err := config.LoadConfig(config.ConfigFilePath)
	if err != nil {
		log.Fatal("Error loading config:", err)
	}

	// Ensure the homepage exists
	if err := handlers.EnsureHomepageExists(cfg); err != nil {
		log.Fatal("Error creating homepage:", err)
	}

	// Ensure static assets exist in data directory
	if err := static.EnsureStaticAssetsExist(cfg.Wiki.RootDir); err != nil {
		log.Fatal("Error copying static assets:", err)
	}

	// Update handlers with config
	handlers.InitHandlers(cfg)

	// Setup all routes
	routes.SetupRoutes(cfg)

	// Start the server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	if cfg.Server.SSL && cfg.Server.SSLCert != "" && cfg.Server.SSLKey != "" {
		fmt.Printf("HTTPS server starting on %s...\n", addr)
		if err := http.ListenAndServeTLS(addr, cfg.Server.SSLCert, cfg.Server.SSLKey, nil); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Printf("HTTP server starting on %s...\n", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Fatal(err)
		}
	}
}
