package roles

// Role constants for user permissions
const (
	// RoleAdmin can do anything from document actions to changing settings and creating/deleting comments
	RoleAdmin = "admin"
	
	// RoleEditor can only do document actions and post comments
	RoleEditor = "editor"
	
	// RoleViewer can only view documents and post comments
	RoleViewer = "viewer"
)
