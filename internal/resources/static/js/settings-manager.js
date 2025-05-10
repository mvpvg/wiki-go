// Settings Management Module
// Handles settings dialog and form functionality including tabs and hotkeys

document.addEventListener('DOMContentLoaded', function() {
    'use strict';

    // Global variables
    let maxFileUploadSizeMB = 20; // Default value, will be updated from settings
    let maxFileUploadSizeBytes = maxFileUploadSizeMB * 1024 * 1024;
    let disableFileUploadChecking = false; // Default value, will be updated from settings

    // Settings elements
    const settingsButton = document.querySelector('.settings-button');
    const settingsDialog = document.querySelector('.settings-dialog');
    const closeSettingsDialog = settingsDialog.querySelector('.close-dialog');
    const cancelSettingsButtons = settingsDialog.querySelectorAll('.cancel-settings');
    const generalSettingsForm = document.getElementById('wikiSettingsForm');
    const contentSettingsForm = document.getElementById('contentSettingsForm');
    const settingsErrorMessage = settingsDialog.querySelector('.error-message');
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabPanes = document.querySelectorAll('.tab-pane');

    // Tab switching
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabId = this.getAttribute('data-tab');

            // Remove active class from all tabs
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanes.forEach(pane => pane.classList.remove('active'));

            // Add active class to current tab
            this.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        });
    });

    // Show settings dialog
    if (settingsButton) {
        settingsButton.addEventListener('click', async function() {
            try {
                // Check if user is authenticated
                const authResponse = await fetch('/api/check-auth');
                if (authResponse.status === 401) {
                    // Show login dialog
                    window.Auth.showLoginDialog(() => {
                        // After login, check if admin
                        window.Auth.checkIfUserIsAdmin().then(isAdmin => {
                            if (isAdmin) {
                                loadSettings();
                                // Update toolbar buttons after login
                                window.Auth.updateToolbarButtons();
                            } else {
                                window.Auth.showAdminOnlyError();
                            }
                        });
                    });
                    return;
                }

                // User is authenticated, check if admin
                const isAdmin = await window.Auth.checkIfUserIsAdmin();
                if (isAdmin) {
                    loadSettings();

                    // Explicitly reset and activate the first tab when opening settings
                    setTimeout(() => {
                        const firstTabButton = document.querySelector('.settings-tabs .tab-button[data-tab="general-tab"]');
                        const firstTabPane = document.getElementById('general-tab');

                        if (firstTabButton && firstTabPane) {
                            // Reset all tabs first
                            document.querySelectorAll('.settings-tabs .tab-button').forEach(btn => {
                                btn.classList.remove('active');
                            });
                            document.querySelectorAll('.tab-pane').forEach(pane => {
                                pane.classList.remove('active');
                            });

                            // Activate the first tab
                            firstTabButton.classList.add('active');
                            firstTabPane.classList.add('active');
                        }
                    }, 50); // Small delay to ensure dialog is rendered
                } else {
                    window.Auth.showAdminOnlyError();
                }
            } catch (error) {
                console.error('Error:', error);
                alert('Failed to check authentication status');
            }
        });
    }

    // Close dialog when clicking close button or cancel
    if (closeSettingsDialog) {
        closeSettingsDialog.addEventListener('click', hideSettingsDialog);
    }

    cancelSettingsButtons.forEach(button => {
        if (button) {
            button.addEventListener('click', hideSettingsDialog);
        }
    });

    // Escape key is now handled by keyboard-shortcuts.js

    // Function to collect all settings from both forms
    function collectAllSettings() {
        const wikiSettings = {
            title: document.getElementById('wikiTitle').value.trim(),
            owner: document.getElementById('wikiOwner').value.trim(),
            notice: document.getElementById('wikiNotice').value.trim(),
            timezone: document.getElementById('wikiTimezone').value.trim(),
            private: document.getElementById('wikiPrivate').checked,
            disable_comments: document.getElementById('wikiDisableComments').checked,
            disable_file_upload_checking: document.getElementById('wikiDisableFileUploadChecking').checked,
            max_versions: parseInt(document.getElementById('wikiMaxVersions').value, 10) || 0,
            max_upload_size: parseInt(document.getElementById('wikiMaxUploadSize').value, 10) || 20,
            language: document.getElementById('wikiLanguage').value
        };

        // Validate
        if (!wikiSettings.title || !wikiSettings.owner || !wikiSettings.notice || !wikiSettings.timezone) {
            return { valid: false, error: 'All fields are required' };
        }

        // Validate max_versions
        if (isNaN(wikiSettings.max_versions) || wikiSettings.max_versions < 0) {
            return { valid: false, error: 'Document versions must be a non-negative number' };
        }

        return { valid: true, settings: wikiSettings };
    }

    // Handle general settings form submission
    if (generalSettingsForm) {
        generalSettingsForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            await saveSettings();
        });
    }

    // Handle content settings form submission
    if (contentSettingsForm) {
        contentSettingsForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            await saveSettings();
        });
    }

    // Save settings function
    async function saveSettings() {
        const result = collectAllSettings();

        if (!result.valid) {
            settingsErrorMessage.textContent = result.error;
            settingsErrorMessage.style.display = 'block';
            return false;
        }

        const wikiSettings = result.settings;

        // Capture current language for comparison
        const currentLanguage = document.documentElement.lang;
        const newLanguage = wikiSettings.language;
        const languageChanged = currentLanguage !== newLanguage;

        try {
            const response = await fetch('/api/settings/wiki', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(wikiSettings)
            });

            if (response.ok) {
                // If language changed, close settings and reload the page
                if (languageChanged) {
                    // Close settings dialog
                    hideSettingsDialog();

                    // Reload the page to apply language changes
                    window.location.reload();
                } else {
                    // Reload the page to show updated settings
                    window.location.reload();
                }
                return true;
            } else {
                const errorData = await response.json().catch(() => null);
                if (errorData && errorData.message) {
                    settingsErrorMessage.textContent = errorData.message;
                } else {
                    settingsErrorMessage.textContent = 'Failed to save settings';
                }
                settingsErrorMessage.style.display = 'block';
                return false;
            }
        } catch (error) {
            console.error('Error saving settings:', error);
            settingsErrorMessage.textContent = 'An error occurred while saving settings';
            settingsErrorMessage.style.display = 'block';
            return false;
        }
    }

    // Function to load settings from the server
    async function loadSettings() {
        try {
            const response = await fetch('/api/settings/wiki');
            if (!response.ok) {
                throw new Error('Failed to fetch settings');
            }

            const settings = await response.json();

            // Populate general form fields
            document.getElementById('wikiTitle').value = settings.title || '';
            document.getElementById('wikiOwner').value = settings.owner || '';
            document.getElementById('wikiNotice').value = settings.notice || '';
            document.getElementById('wikiTimezone').value = settings.timezone || '';
            document.getElementById('wikiLanguage').value = settings.language || 'en';

            // Populate content form fields
            document.getElementById('wikiPrivate').checked = settings.private || false;
            document.getElementById('wikiDisableComments').checked = settings.disable_comments || false;
            document.getElementById('wikiDisableFileUploadChecking').checked = settings.disable_file_upload_checking || false;

            // Handle max_versions specifically to account for 0 value
            document.getElementById('wikiMaxVersions').value = settings.max_versions !== undefined ? settings.max_versions : 10;

            // Handle max_upload_size
            document.getElementById('wikiMaxUploadSize').value = settings.max_upload_size !== undefined ? settings.max_upload_size : 20;

            // Update global variables for max file size
            maxFileUploadSizeMB = settings.max_upload_size || 20;
            maxFileUploadSizeBytes = maxFileUploadSizeMB * 1024 * 1024;

            // Update the file upload checking setting
            if (settings && settings.disable_file_upload_checking !== undefined) {
                disableFileUploadChecking = settings.disable_file_upload_checking;
                console.log(`Disable file upload checking: ${disableFileUploadChecking}`);
            }

            // Load users for the users tab
            loadUsers();

            // Show dialog
            settingsDialog.classList.add('active');
            settingsErrorMessage.style.display = 'none';

            // Ensure the first tab is active by default
            const firstTabButton = document.querySelector('.settings-tabs .tab-button[data-tab="general-tab"]');
            const firstTabPane = document.getElementById('general-tab');

            if (firstTabButton && firstTabPane) {
                // Reset all tabs first
                document.querySelectorAll('.settings-tabs .tab-button').forEach(btn => {
                    btn.classList.remove('active');
                });
                document.querySelectorAll('.settings-dialog .tab-pane').forEach(pane => {
                    pane.classList.remove('active');
                });

                // Activate the first tab
                firstTabButton.classList.add('active');
                firstTabPane.classList.add('active');
            }
        } catch (error) {
            console.error('Error loading settings:', error);
            alert('Failed to load settings');
        }
    }

    // Function to hide settings dialog
    function hideSettingsDialog() {
        settingsDialog.classList.remove('active');
    }

    // User Management Functions
    const usersList = document.querySelector('.users-list');
    const userForm = document.getElementById('userForm');
    const userFormTitle = document.getElementById('user-form-title');
    const userFormMode = document.getElementById('userFormMode');
    const userFormUsernameInput = document.getElementById('userFormUsername');
    const passwordInput = document.getElementById('userFormPassword');
    const passwordHelp = document.getElementById('password-help');
    const userRoleSelect = document.getElementById('userRole');
    const saveUserBtn = document.getElementById('saveUserBtn');
    const cancelUserBtn = document.getElementById('cancelUserBtn');

    // Add event listeners for user management
    if (userForm) {
        userForm.addEventListener('submit', handleUserFormSubmit);
    }

    if (cancelUserBtn) {
        cancelUserBtn.addEventListener('click', resetUserForm);
    }

    // Add "Add User" button to the users list container
    const usersListContainer = document.querySelector('.users-list-container');
    if (usersListContainer) {
        const addUserBtn = document.createElement('button');
        addUserBtn.className = 'add-user-btn';
        addUserBtn.setAttribute('data-i18n', 'users.add_new'); // Add data-i18n attribute for automatic translation
        addUserBtn.textContent = 'Add New User'; // Default text
        addUserBtn.addEventListener('click', resetUserForm);
        usersListContainer.insertBefore(addUserBtn, usersListContainer.querySelector('.users-list'));
    }

    // Function to load users list
    async function loadUsers() {
        try {
            const response = await fetch('/api/users');
            if (!response.ok) {
                throw new Error('Failed to load users');
            }
            const data = await response.json();
            renderUsersList(data.users);

            // Create "Add New User" button if it doesn't exist
            if (!usersListContainer.querySelector('.add-user-btn')) {
                const addUserBtn = document.createElement('button');
                addUserBtn.className = 'add-user-btn';
                addUserBtn.setAttribute('data-i18n', 'users.add_new'); // Add data-i18n attribute for automatic translation
                addUserBtn.textContent = 'Add New User'; // Default text
                addUserBtn.addEventListener('click', resetUserForm);
                usersListContainer.insertBefore(addUserBtn, usersListContainer.querySelector('.users-list'));

                // Manually translate the button if i18n is already initialized
                if (window.i18n) {
                    window.i18n.translateElement(addUserBtn);
                }
            }
        } catch (error) {
            console.error('Error loading users:', error);
        }
    }

    // Function to render the users list
    function renderUsersList(users) {
        if (!usersList) return;

        if (!users || users.length === 0) {
            usersList.innerHTML = '<div class="empty-message">No users found</div>';
            return;
        }

        // Get current username from session for highlighting
        const currentUsername = document.cookie
            .split('; ')
            .find(row => row.startsWith('session_user='))
            ?.split('=')[1];

        // Sort users: admins first, then editors, then viewers, then alphabetically
        users.sort((a, b) => {
            // Get roles with fallback for backward compatibility
            const roleA = a.role || (a.is_admin ? 'admin' : 'viewer');
            const roleB = b.role || (b.is_admin ? 'admin' : 'viewer');
            
            // Define role priority (admin > editor > viewer)
            const rolePriority = { 'admin': 0, 'editor': 1, 'viewer': 2 };
            
            // Sort by role priority first
            if (rolePriority[roleA] !== rolePriority[roleB]) {
                return rolePriority[roleA] - rolePriority[roleB];
            }
            
            // If same role, sort alphabetically
            return a.username.localeCompare(b.username);
        });

        const html = users.map(user => {
            const isCurrentUser = user.username === currentUsername;
            // Get role with fallback for backward compatibility
            const role = user.role || (user.is_admin ? 'admin' : 'viewer');
            
            // Get role display name
            let roleDisplay = role.charAt(0).toUpperCase() + role.slice(1);
            if (window.i18n && window.i18n.t) {
                roleDisplay = window.i18n.t(`users.role_${role}`);
            }
            
            // Set role badge class based on role
            const roleBadgeClass = `role-badge role-${role}`;
            
            return `
                <div class="user-item" data-username="${user.username}">
                    <div class="user-info">
                        <span class="username">${user.username}</span>
                        <span class="${roleBadgeClass}">${roleDisplay}</span>
                        ${isCurrentUser ? `<span class="current-user-badge">${window.i18n ? window.i18n.t('common.you') : 'You'}</span>` : ''}
                    </div>
                    <div class="user-actions">
                        <button class="edit-user-btn" title="Edit user" data-username="${user.username}" data-user='${JSON.stringify({role: role, is_admin: user.is_admin})}'>
                            <i class="fa fa-pencil"></i>
                        </button>
                        ${!isCurrentUser ? `
                        <button class="delete-user-btn" title="Delete user" data-username="${user.username}">
                            <i class="fa fa-trash"></i>
                        </button>
                        ` : ''}
                    </div>
                </div>
            `;
        }).join('');

        usersList.innerHTML = html;

        // Add event listeners to the edit and delete buttons
        usersList.querySelectorAll('.edit-user-btn').forEach(button => {
            button.addEventListener('click', () => {
                const username = button.getAttribute('data-username');
                const userData = JSON.parse(button.getAttribute('data-user'));
                editUser(username, userData);
            });
        });

        usersList.querySelectorAll('.delete-user-btn').forEach(button => {
            button.addEventListener('click', () => {
                const username = button.getAttribute('data-username');
                deleteUser(username);
            });
        });
    }

    // Function to reset the user form (for adding a new user)
    function resetUserForm() {
        userFormMode.value = 'create';
        userFormTitle.textContent = 'Add New User';
        userFormTitle.setAttribute('data-i18n', 'users.add_user_title');
        userFormUsernameInput.value = '';
        userFormUsernameInput.disabled = false;
        passwordInput.value = '';
        passwordHelp.style.display = 'none';
        passwordInput.required = true;
        userRoleSelect.value = 'viewer'; // Default to viewer
        saveUserBtn.textContent = 'Add User';
        saveUserBtn.setAttribute('data-i18n', 'users.add_button');

        // Change button text to "Clear" in add mode
        cancelUserBtn.textContent = 'Clear';
        cancelUserBtn.setAttribute('data-i18n', 'users.clear_button');

        // Apply translations if i18n is available
        if (window.i18n) {
            window.i18n.translateElement(userFormTitle);
            window.i18n.translateElement(saveUserBtn);
            window.i18n.translateElement(cancelUserBtn);
        }

        // Switch to users tab
        const usersTabButton = document.querySelector('.tab-button[data-tab="users-tab"]');
        if (usersTabButton) {
            usersTabButton.click();
        }
    }

    // Function to set up the form for editing a user
    function editUser(username, user) {
        userFormMode.value = 'update';
        userFormTitle.removeAttribute('data-i18n'); // Remove data-i18n as we're using a dynamic title
        userFormTitle.textContent = `Edit User: ${username}`;
        userFormUsernameInput.value = username;
        userFormUsernameInput.disabled = true;
        passwordInput.value = '';
        passwordHelp.style.display = 'block';
        passwordInput.required = false;
        
        // Set the role dropdown value
        if (user.role) {
            userRoleSelect.value = user.role;
        } else {
            // For backward compatibility
            userRoleSelect.value = user.is_admin ? 'admin' : 'viewer';
        }
        saveUserBtn.textContent = 'Update User';
        saveUserBtn.setAttribute('data-i18n', 'users.update_button');

        // Use "Clear" for consistency with add mode, since the outcome is similar
        cancelUserBtn.textContent = 'Clear';
        cancelUserBtn.setAttribute('data-i18n', 'users.clear_button');

        // Apply translations if i18n is available
        if (window.i18n) {
            window.i18n.translateElement(saveUserBtn);
            window.i18n.translateElement(cancelUserBtn);

            // For the title, we need to use a different approach since it includes the username
            if (window.i18n.t) {
                const editUserTitle = window.i18n.t('users.edit_user_title');
                userFormTitle.textContent = `${editUserTitle}: ${username}`;
            }
        }

        // Switch to users tab
        const usersTabButton = document.querySelector('.tab-button[data-tab="users-tab"]');
        if (usersTabButton) {
            usersTabButton.click();
        }
    }

    // Function to handle form submission (create or update user)
    async function handleUserFormSubmit(e) {
        e.preventDefault();

        const mode = userFormMode.value;
        const username = userFormUsernameInput.value.trim();
        const password = passwordInput.value;
        const role = userRoleSelect.value;

        if (!username) {
            window.DialogSystem.showMessageDialog("Form Error", "Username is required");
            return;
        }

        if (mode === 'create' && !password) {
            window.DialogSystem.showMessageDialog("Form Error", "Password is required for new users");
            return;
        }

        try {
            let response;

            if (mode === 'create') {
                // Create new user
                response = await fetch('/api/users', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username,
                        password,
                        role: role
                    })
                });
            } else {
                // Update existing user
                response = await fetch('/api/users', {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username,
                        new_password: password || undefined,
                        role: role
                    })
                });
            }

            if (!response.ok) {
                const errorData = await response.json().catch(() => null);
                throw new Error(errorData?.message || `Failed to ${mode} user`);
            }

            // Reload users and reset form
            loadUsers();
            resetUserForm();

            // Check if default password is still in use after user creation/update
            window.Auth.checkDefaultPassword();
        } catch (error) {
            console.error(`Error ${mode === 'create' ? 'creating' : 'updating'} user:`, error);
            window.DialogSystem.showMessageDialog(
                "User Operation Failed",
                error.message || `Failed to ${mode} user`
            );
        }
    }

    // Function to delete a user
    async function deleteUser(username) {
        const title = window.i18n ? window.i18n.t('delete_user.title') : "Delete User";
        const message = window.i18n ?
            window.i18n.t('delete_user.confirm_message').replace('{0}', username) :
            `Are you sure you want to delete user "${username}"? This action cannot be undone.`;

        window.DialogSystem.showConfirmDialog(
            title,
            message,
            async (confirmed) => {
                if (!confirmed) {
                    return;
                }

                try {
                    const response = await fetch(`/api/users?username=${encodeURIComponent(username)}`, {
                        method: 'DELETE'
                    });

                    if (!response.ok) {
                        const errorData = await response.json().catch(() => null);
                        throw new Error(errorData?.message || 'Failed to delete user');
                    }

                    // Reload users list
                    loadUsers();
                    // Reset form in case the deleted user was being edited
                    resetUserForm();
                    // Check if default password is still in use after user deletion
                    window.Auth.checkDefaultPassword();
                } catch (error) {
                    console.error('Error deleting user:', error);
                    window.DialogSystem.showMessageDialog("Delete Failed", error.message || 'Failed to delete user');
                }
            }
        );
    }

    // Function to fetch max upload size from server
    async function fetchMaxUploadSize() {
        try {
            const response = await fetch('/api/settings/wiki');
            if (response.ok) {
                const settings = await response.json();
                if (settings && settings.max_upload_size) {
                    maxFileUploadSizeMB = settings.max_upload_size;
                    maxFileUploadSizeBytes = maxFileUploadSizeMB * 1024 * 1024;
                    console.log(`Max upload size updated to ${maxFileUploadSizeMB}MB`);
                }
                // Update the file upload checking setting
                if (settings && settings.disable_file_upload_checking !== undefined) {
                    disableFileUploadChecking = settings.disable_file_upload_checking;
                    console.log(`Disable file upload checking: ${disableFileUploadChecking}`);
                }
            } else if (response.status === 401) {
                // User is not authenticated or not an admin, use the default value
                console.log(`Using default max upload size of ${maxFileUploadSizeMB}MB`);
                console.log(`Using default file upload checking (enabled)`);
            }
        } catch (error) {
            console.error('Error fetching settings:', error);
        }
    }

    // Make functions available globally
    window.SettingsManager = {
        hideSettingsDialog,
        fetchMaxUploadSize,
        loadSettings,
        maxFileUploadSizeMB: () => maxFileUploadSizeMB,
        maxFileUploadSizeBytes: () => maxFileUploadSizeBytes,
        isFileUploadCheckingDisabled: () => disableFileUploadChecking
    };
});
