// Document Management Module for Wiki-Go
// Handles document creation and deletion
(function() {
    'use strict';

    // Module state variables
    let newDocButton;
    let newDocDialog;
    let newDocForm;
    let closeNewDocDialog;
    let cancelNewDocButton;
    let docTitleInput;
    let docPathInput;
    let docSlugInput;
    let newDocErrorMessage;

    let deleteButton;
    let confirmationDialog;
    let deleteConfirmBtn;
    let cancelDeleteBtn;

    // Initialize module when DOM is loaded
    document.addEventListener('DOMContentLoaded', function() {
        // New Document functionality
        newDocButton = document.querySelector('.new-document');
        newDocDialog = document.querySelector('.new-document-dialog');
        newDocForm = document.getElementById('newDocumentForm');
        closeNewDocDialog = newDocDialog?.querySelector('.close-dialog');
        cancelNewDocButton = newDocDialog?.querySelector('.cancel-new-doc');
        docTitleInput = document.getElementById('docTitle');
        docPathInput = document.getElementById('docPath');
        docSlugInput = document.getElementById('docSlug');
        newDocErrorMessage = newDocDialog?.querySelector('.error-message');

        // Delete Document functionality
        deleteButton = document.querySelector('.delete-document');
        confirmationDialog = document.querySelector('.confirmation-dialog');
        deleteConfirmBtn = document.querySelector('.confirmation-dialog .delete-confirm');
        cancelDeleteBtn = document.querySelector('.confirmation-dialog .cancel-delete');

        // Initialize components if they exist
        if (docTitleInput && docSlugInput) {
            // Note: Slug generation is now handled by slugify.js
            // No event listeners needed here
        }

        // Initialize new document button
        if (newDocButton) {
            newDocButton.addEventListener('click', async function() {
                try {
                    // Check if user is authenticated
                    const authResponse = await fetch('/api/check-auth');
                    if (authResponse.status === 401) {
                        // Show login dialog
                        window.Auth.showLoginDialog(() => {
                            // After login, check if user has editor or admin role
                            window.Auth.checkUserRole('editor').then(canEdit => {
                                if (canEdit) {
                                    showNewDocDialog();
                                    // Update toolbar buttons after login
                                    window.Auth.updateToolbarButtons();
                                } else {
                                    window.Auth.showPermissionError('editor');
                                }
                            });
                        });
                        return;
                    }

                    // User is authenticated, check if user has editor or admin role
                    const canEdit = await window.Auth.checkUserRole('editor');
                    if (canEdit) {
                        showNewDocDialog();
                    } else {
                        window.Auth.showPermissionError('editor');
                    }
                } catch (error) {
                    console.error('Error:', error);
                    alert('Failed to check authentication status');
                }
            });
        }

        // Close dialog when clicking close button or cancel
        if (closeNewDocDialog) {
            closeNewDocDialog.addEventListener('click', hideNewDocDialog);
        }

        if (cancelNewDocButton) {
            cancelNewDocButton.addEventListener('click', hideNewDocDialog);
        }

        // Escape key is now handled by keyboard-shortcuts.js

        // Handle new document form submission
        if (newDocForm) {
            newDocForm.addEventListener('submit', async function(e) {
                e.preventDefault();

                // Get values
                const title = docTitleInput.value.trim();
                let path = docPathInput.value.trim();
                let slug = docSlugInput.value.trim();

                // Validate - only title is required
                if (!title) {
                    newDocErrorMessage.textContent = 'Title is required';
                    newDocErrorMessage.style.display = 'block';
                    return;
                }

                // If slug is empty, use title for server-side transliteration
                if (!slug) {
                    slug = title;
                }

                // Remove leading and trailing slashes from path if it's not empty
                if (path) {
                    path = path.replace(/^\/|\/$/g, '');
                }

                // Combine path and slug
                // If path is empty, just use the slug (creates document at root level)
                const fullPath = path ? `${path}/${slug}` : slug;

                try {
                    const response = await fetch('/api/document/create', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            title: title,
                            path: fullPath
                        })
                    });

                    if (response.ok) {
                        const result = await response.json();
                        // Redirect to the new document
                        window.location.href = result.url;
                    } else {
                        const errorData = await response.json().catch(() => null);
                        if (errorData && errorData.message) {
                            let errorMsg = errorData.message;
                            // Check if it's a "Document already exists" error
                            if (errorMsg.includes("Document already exists")) {
                                errorMsg = window.i18n ? window.i18n.t('new_doc.already_exists') : 'Document already exists';
                            } else if (errorData.error) {
                                // Add error details if available
                                errorMsg += `: ${errorData.error}`;
                            }
                            newDocErrorMessage.textContent = errorMsg;
                        } else {
                            newDocErrorMessage.textContent = 'Failed to create document';
                        }
                        newDocErrorMessage.style.display = 'block';
                        console.error('Document creation error:', errorData);
                    }
                } catch (error) {
                    console.error('Error creating document:', error);
                    newDocErrorMessage.textContent = 'An error occurred. Please try again.';
                    newDocErrorMessage.style.display = 'block';
                }
            });
        }

        // Initialize delete document button
        if (deleteButton) {
            deleteButton.addEventListener('click', function() {
                showDeleteConfirmDialog();
            });
        }

        // Initialize delete confirmation buttons
        if (cancelDeleteBtn) {
            cancelDeleteBtn.addEventListener('click', function() {
                hideConfirmationDialog();
            });
        }

        if (deleteConfirmBtn) {
            deleteConfirmBtn.addEventListener('click', handleDocumentDeletion);
        }

        // Escape key is now handled by keyboard-shortcuts.js
    });

    // Show new document dialog
    function showNewDocDialog() {
        newDocDialog.classList.add('active');
        newDocErrorMessage.style.display = 'none';
        newDocForm.reset();

        // Pre-populate path with current path
        const currentPath = window.location.pathname;
        if (currentPath && currentPath !== '/') {
            // Remove leading and trailing slashes
            let path = currentPath.replace(/^\/|\/$/g, '');
            // If current path ends with a filename, get the directory
            if (!path.endsWith('/')) {
                path = path.substring(0, path.lastIndexOf('/'));
            }
            docPathInput.value = path;
        }

        // Focus on title field
        setTimeout(() => {
            docTitleInput.focus();
        }, 100);
    }

    // Hide new document dialog
    function hideNewDocDialog() {
        newDocDialog.classList.remove('active');
    }

    // Show delete confirmation dialog
    function showDeleteConfirmDialog() {
        confirmationDialog.classList.add('active');
    }

    // Hide delete confirmation dialog
    function hideConfirmationDialog() {
        confirmationDialog.classList.remove('active');
    }

    // Handle document deletion
    async function handleDocumentDeletion() {
        try {
            const isHomepage = window.location.pathname === '/';

            // Don't allow deleting the homepage
            if (isHomepage) {
                alert('The homepage cannot be deleted.');
                hideConfirmationDialog();
                return;
            }

            const apiPath = `/api/document${window.location.pathname}`;

            const response = await fetch(apiPath, {
                method: 'DELETE',
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => null);
                throw new Error(errorData?.message || 'Failed to delete document');
            }

            // Handle successful deletion
            // Redirect to parent directory
            const pathParts = window.location.pathname.split('/').filter(Boolean);
            pathParts.pop(); // Remove the last part (document name)
            const parentPath = pathParts.length > 0 ? '/' + pathParts.join('/') : '/';

            window.location.href = parentPath;
        } catch (error) {
            console.error('Error deleting document:', error);
            alert(error.message || 'Failed to delete document');
            hideConfirmationDialog();
        }
    }

    // Expose public API
    window.DocumentManager = {
        showNewDocDialog: showNewDocDialog,
        hideNewDocDialog: hideNewDocDialog,
        showDeleteConfirmDialog: showDeleteConfirmDialog,
        hideConfirmationDialog: hideConfirmationDialog
    };
})();
