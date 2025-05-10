// Custom CodeMirror Editor Module
let editor = null;
let previewElement = null;
let previewContent = null;
let tablePickerElement = null;
let emojiPickerElement = null;
let docPickerElement = null;
// Anchor picker element
let anchorPickerElement = null;

// Emoji data for picker
let emojiData = [];
// Document data for picker
let documentData = [];

// Global emoji cache
const EmojiCache = {
    data: null,
    preloadPromise: null,

    // Get emoji data - returns a promise
    getData: function() {
        // If we already have data, return it
        if (this.data) {
            return Promise.resolve(this.data);
        }

        // If we're already loading, return the existing promise
        if (this.preloadPromise) {
            return this.preloadPromise;
        }

        // Start a new load
        this.preloadPromise = this.fetchEmojiData()
            .then(data => {
                this.data = data;
                return data;
            })
            .catch(err => {
                console.error('Error loading emoji data:', err);
                // Clear the promise so we can try again
                this.preloadPromise = null;
                return [];
            });

        return this.preloadPromise;
    },

    // Fetch emoji data from server
    fetchEmojiData: async function() {
        try {
            console.log('Fetching emoji data from server');
            const response = await fetch('/api/data/emojis');
            if (!response.ok) {
                throw new Error('Failed to fetch emoji data');
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error fetching emoji data:', error);
            return [];
        }
    }
};

// Helper functions for editor toolbar actions
function wrapText(cm, prefix = '', suffix = '', placeholder = '') {
    const selection = cm.getSelection();
    if (selection) {
        cm.replaceSelection(`${prefix}${selection}${suffix}`);
    } else {
        const cursor = cm.getCursor();
        cm.replaceRange(prefix + placeholder + suffix, cursor);
        // Place cursor between prefix and suffix so the user can start typing.
        cm.setCursor(cursor.line, cursor.ch + prefix.length);
    }
    // Ensure the editor keeps focus.
    cm.focus();
}

// Function to add highlight markup
function addHighlight(cm) {
    wrapText(cm, '==', '==');
}

function addSuperscript(cm) {
    wrapText(cm, '^', '^');
}

function addSubscript(cm) {
    wrapText(cm, '~', '~');
}

function addRecentEdits(cm) {
    var cursor = cm.getCursor();
    cm.replaceRange(":::stats recent=5:::\n", cursor);
    // Ensure editor retains focus
    cm.focus();
}

function addTotal(cm) {
    var cursor = cm.getCursor();
    cm.replaceRange(":::stats count=*:::\n", cursor);
    // Ensure editor retains focus
    cm.focus();
}

// Function to insert emoji
function insertEmoji(emoji) {
    if (!editor) return;

    // Insert emoji shortcode at cursor position
    const cursor = editor.getCursor();
    editor.replaceRange(emoji.shortcode + ' ', cursor);

    // Focus the editor
    editor.focus();
}

// Create emoji picker
function createEmojiPicker() {
    const picker = document.createElement('div');
    picker.className = 'emoji-picker';
    picker.style.display = 'none';

    // Create a content container for the emojis
    const emojiContainer = document.createElement('div');
    emojiContainer.className = 'emoji-container';

    // Create a loading message
    const loadingMsg = document.createElement('div');
    loadingMsg.className = 'emoji-loading';
    loadingMsg.textContent = 'Loading emojis...';

    // Add both to the picker
    picker.appendChild(loadingMsg);
    picker.appendChild(emojiContainer);
    document.body.appendChild(picker);
    emojiPickerElement = picker;

    // Load emoji data using our singleton cache
    EmojiCache.getData().then(data => {
        // Save the data globally
        emojiData = data;

        // Show the emoji buttons and hide the loading message
        loadingMsg.style.display = 'none';

        // Create buttons for each emoji
        emojiData.forEach(emoji => {
            // Skip if no shortcodes
            if (!emoji.shortcodes || emoji.shortcodes.length === 0) return;

            const button = document.createElement('button');
            button.className = 'emoji-btn';

            // Get the primary shortcode (first in the array)
            const shortcode = ':' + emoji.shortcodes[0] + ':';
            button.title = shortcode;
            button.textContent = emoji.emoji;

            button.addEventListener('click', () => {
                const emojiObj = {
                    emoji: emoji.emoji,
                    shortcode: shortcode
                };
                insertEmoji(emojiObj);
                hideEmojiPicker();
            });
            emojiContainer.appendChild(button);
        });
    });

    return picker;
}

// Function to show emoji picker
function showEmojiPicker(button) {
    // Preload emoji data to reduce latency
    EmojiCache.getData();

    togglePicker({
        get: () => emojiPickerElement,
        set: (el) => { emojiPickerElement = el; },
        create: createEmojiPicker,
        button,
        closeSelector: '.emoji-button'
    });
}

// Function to hide emoji picker
function hideEmojiPicker() {
    if (emojiPickerElement) {
        emojiPickerElement.style.display = 'none';
        // Reset any transform or size constraints that might have been applied
        emojiPickerElement.style.transform = '';
    }
}

// Function to fetch documents
async function fetchDocuments() {
    try {
        const response = await fetch('/api/documents/list');
        if (!response.ok) {
            if (response.status === 401) {
                throw new Error('Authentication required');
            }
            throw new Error('Failed to fetch documents');
        }
        const data = await response.json();
        if (!data.success) {
            throw new Error(data.message || 'Failed to fetch documents');
        }
        return data.documents || [];
    } catch (error) {
        console.error('Error fetching documents:', error);
        throw error; // Re-throw to allow handling in the caller
    }
}

// Function to insert document link
function insertDocLink(document) {
    if (!editor) return;

    // Get selection (if any) to use as link text
    const selection = editor.getSelection();

    // Build path and fallback title
    let path = document.path;
    const title = document.title || path.split('/').pop();

    // Strip /documents prefix for internal links (except pages)
    if (path.startsWith('/documents')) {
        path = path.replace('/documents', '');
    }

    if (selection) {
        // Replace selection with link
        editor.replaceSelection(`[${selection}](${path})`);
        // Place cursor at end of link
    } else {
        const cursor = editor.getCursor();
        editor.replaceRange(`[${title}](${path})`, cursor);
        // Select the link text so user can change it
        editor.setSelection(
            { line: cursor.line, ch: cursor.ch + 1 },
            { line: cursor.line, ch: cursor.ch + 1 + title.length }
        );
    }

    editor.focus();
}

// Create document picker
function createDocPicker() {
    const picker = document.createElement('div');
    picker.className = 'doc-picker';
    picker.setAttribute('dir', 'auto');
    picker.style.display = 'none';

    // Create a search input
    const searchContainer = document.createElement('div');
    searchContainer.className = 'doc-search-container';

    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.className = 'doc-search-input';
    searchInput.placeholder = window.i18n ? window.i18n.t('docpicker.search_placeholder') : 'Search…';
    searchInput.style.boxSizing = 'border-box';
    searchInput.style.width = '100%';

    searchContainer.appendChild(searchInput);
    picker.appendChild(searchContainer);

    // Create a content container for the documents
    const docsContainer = document.createElement('div');
    docsContainer.className = 'docs-container';
    docsContainer.style.width = '100%';
    docsContainer.style.boxSizing = 'border-box';

    // Create a loading message
    const loadingMsg = document.createElement('div');
    loadingMsg.className = 'docs-loading';
    loadingMsg.textContent = window.i18n ? window.i18n.t('docpicker.loading') : 'Loading...';

    // Add both to the picker
    picker.appendChild(loadingMsg);
    picker.appendChild(docsContainer);
    document.body.appendChild(picker);
    docPickerElement = picker;

    // Check if user has editor or admin role before trying to fetch documents
    window.Auth.checkUserRole('editor').then(canEdit => {
        if (!canEdit) {
            loadingMsg.textContent = window.i18n ? window.i18n.t('docpicker.admin_required') : 'Editor or admin required';
            return;
        }

        // Load document data
        fetchDocuments().then(documents => {
            // Save the data globally
            documentData = documents;

            // Hide loading message
            loadingMsg.style.display = 'none';

            // Function to filter and display documents
            const filterAndDisplay = (query = '') => {
                // Clear previous documents
                docsContainer.innerHTML = '';

                // Filter documents based on search query
                const filteredDocs = query
                    ? documentData.filter(doc =>
                        includesIgnoreCase(doc.title, query) ||
                        includesIgnoreCase(doc.path, query))
                    : documentData;

                if (filteredDocs.length === 0) {
                    const noResults = document.createElement('div');
                    noResults.className = 'no-results';
                    noResults.textContent = window.i18n ? window.i18n.t('docpicker.no_results') : 'No results found';
                    docsContainer.appendChild(noResults);
                    return;
                }

                // Create buttons for each document
                filteredDocs.forEach(doc => {
                    const btn = createDocButton(doc, () => {
                        insertDocLink(doc);
                        hideDocPicker();
                    });
                    docsContainer.appendChild(btn);
                });
            };

            // Initial display of all documents
            filterAndDisplay();

            // Add search functionality
            searchInput.addEventListener('input', (e) => {
                filterAndDisplay(e.target.value);
            });
        }).catch(error => {
            // Show error message
            loadingMsg.textContent = window.i18n ? window.i18n.t('docpicker.error_loading').replace('{0}', error.message || 'Access denied') : 'Error loading documents';
        });
    });

    return picker;
}

// Function to show document picker
function showDocPicker(button) {
    togglePicker({
        get: () => docPickerElement,
        set: (el) => { docPickerElement = el; },
        create: createDocPicker,
        button,
        closeSelector: '.doc-link-button',
        onShow: (picker) => {
            const searchInput = picker.querySelector('.doc-search-input');
            if (searchInput) {
                setTimeout(() => searchInput.focus(), 50);
            }
        }
    });
}

// Function to hide document picker
function hideDocPicker() {
    if (docPickerElement) {
        docPickerElement.style.display = 'none';
        // Reset any transform or size constraints that might have been applied
        docPickerElement.style.transform = '';
    }
}

// Table picker functionality
function createTablePicker() {
    const picker = document.createElement('div');
    picker.className = 'table-picker';
    picker.style.display = 'none';

    for (let i = 0; i < 10; i++) {
        for (let j = 0; j < 10; j++) {
            const cell = document.createElement('div');
            cell.className = 'cell';
            cell.dataset.row = i + 1;
            cell.dataset.col = j + 1;
            cell.addEventListener('mouseover', () => highlightCells(cell));
            cell.addEventListener('click', () => insertTable(i + 1, j + 1));
            picker.appendChild(cell);
        }
        picker.appendChild(document.createElement('br'));
    }

    document.body.appendChild(picker);
    tablePickerElement = picker;
    return picker;
}

function highlightCells(cell) {
    const row = parseInt(cell.dataset.row);
    const col = parseInt(cell.dataset.col);
    const cells = document.querySelectorAll('.table-picker .cell');
    cells.forEach(c => {
        if (parseInt(c.dataset.row) <= row && parseInt(c.dataset.col) <= col) {
            c.classList.add('active');
        } else {
            c.classList.remove('active');
        }
    });
}

function insertTable(rows, cols) {
    if (!editor) return;

    let table = '\n';
    // Header
    table += '| ' + Array(cols).fill('Header').join(' | ') + ' |\n';
    // Separator
    table += '| ' + Array(cols).fill('---').join(' | ') + ' |\n';
    // Rows
    for (let i = 0; i < rows; i++) {
        table += '| ' + Array(cols).fill('Cell').join(' | ') + ' |\n';
    }
    editor.replaceSelection(table);
    if (tablePickerElement) {
        tablePickerElement.style.display = 'none';
    }

    // Make sure editor gets focus after inserting table
    setTimeout(() => editor.focus(), 10);
}

function showTablePicker(button) {
    togglePicker({
        get: () => tablePickerElement,
        set: (el) => { tablePickerElement = el; },
        create: createTablePicker,
        button,
        closeSelector: '.table-button'
    });
}

// Create custom toolbar
function createToolbar(container) {
    const toolbar = document.createElement('div');
    toolbar.className = 'editor-toolbar custom-toolbar';

    // Define toolbar buttons
    const buttons = [
        { icon: 'fa-header', action: 'heading', title: 'Heading' },
        { icon: 'fa-bold', action: 'bold', title: 'Bold' },
        { icon: 'fa-italic', action: 'italic', title: 'Italic' },
        { icon: 'fa-paint-brush', action: 'highlight', title: 'Highlight Text' },
        { icon: 'fa-strikethrough', action: 'strikethrough', title: 'Strikethrough' },
        { icon: 'fa-subscript', action: 'subscript', title: 'Add Subscript' },
        { icon: 'fa-superscript', action: 'superscript', title: 'Add Superscript' },
        { type: 'separator' },
        { icon: 'fa-code', action: 'code', title: 'Code' },
        { icon: 'fa-quote-left', action: 'quote', title: 'Quote' },
        { icon: 'fa-list-ul', action: 'unordered-list', title: 'Unordered List' },
        { icon: 'fa-list-ol', action: 'ordered-list', title: 'Ordered List' },
        { type: 'separator' },
        { icon: 'fa-picture-o', action: 'image', title: 'Image' },
        { icon: 'fa-link', action: 'link', title: 'Link' },
        { icon: 'fa-anchor', action: 'anchor-link', title: 'Link to Heading' },
        { icon: 'fa-file-text-o', action: 'doc-link', title: 'Link to Document' },
        { icon: 'fa-smile-o', action: 'emoji', title: 'Insert Emoji' },
        { type: 'separator' },
        { icon: 'fa-th', action: 'table', title: 'Insert Custom Table', id: 'insert-table' },
        { icon: 'fa-minus', action: 'horizontal-rule', title: 'Horizontal Rule' },
        { type: 'separator' },
        { icon: 'fa-clock-o', action: 'recent-edits', title: 'Insert Recent Edits' },
        { icon: 'fa-book', action: 'total', title: 'Insert Total Number of Documents' },
        { type: 'separator' },
        { icon: 'fa-undo', action: 'undo', title: 'Undo' },
        { icon: 'fa-repeat', action: 'redo', title: 'Redo' },
        { type: 'separator' },
        { icon: 'fa-eye', action: 'preview', title: 'Toggle Preview', id: 'toggle-preview' }
    ];

    buttons.forEach(button => {
        if (button.type === 'separator') {
            const separator = document.createElement('i');
            separator.className = 'separator';
            toolbar.appendChild(separator);
        } else {
            const btn = document.createElement('button');
            if (button.id) {
                btn.id = button.id;
            }
            btn.className = `toolbar-button ${button.action}-button`;
            btn.dataset.action = button.action;
            btn.title = button.title;

            const icon = document.createElement('i');
            icon.className = `fa ${button.icon}`;
            btn.appendChild(icon);

            toolbar.appendChild(btn);
        }
    });

    container.appendChild(toolbar);
    return toolbar;
}

// Add event listeners to toolbar buttons
function setupToolbarActions(toolbar) {
    if (!editor || !toolbar) return;

    if (toolbar._delegateSetup) return; // Prevent double-initialisation

    // Executes the requested action.
    const exec = (action, button) => {
        switch (action) {
            case 'bold':
                wrapText(editor, '**', '**');
                break;
            case 'italic':
                wrapText(editor, '*', '*');
                break;
            case 'strikethrough':
                wrapText(editor, '~~', '~~');
                break;
            case 'highlight':
                addHighlight(editor);
                break;
            case 'subscript':
                addSubscript(editor);
                break;
            case 'superscript':
                addSuperscript(editor);
                break;
            case 'heading': {
                const cursor = editor.getCursor();
                const line = editor.getLine(cursor.line);
                const headingMatch = line.match(/^(#+)\s/);

                if (headingMatch) {
                    const prefix = headingMatch[1];
                    const contentStart = prefix.length + 1; // +1 for space
                    const content = line.substring(contentStart);

                    if (prefix.length < 6) {
                        editor.replaceRange('#' + prefix + ' ' + content,
                            { line: cursor.line, ch: 0 },
                            { line: cursor.line, ch: line.length });
                    } else {
                        editor.replaceRange(content,
                            { line: cursor.line, ch: 0 },
                            { line: cursor.line, ch: line.length });
                    }
                } else {
                    editor.replaceRange('# ' + line,
                        { line: cursor.line, ch: 0 },
                        { line: cursor.line, ch: line.length });
                }
                editor.focus();
                break;
            }
            case 'code': {
                const sel = editor.getSelection();
                if (sel) {
                    if (sel.indexOf('\n') !== -1) {
                        editor.replaceSelection("```\n" + sel + "\n```");
                    } else {
                        editor.replaceSelection("`" + sel + "`");
                    }
                } else {
                    const cursor = editor.getCursor();
                    editor.replaceRange("``", cursor);
                    editor.setCursor(cursor.line, cursor.ch + 1);
                }
                editor.focus();
                break;
            }
            case 'quote': {
                const sel = editor.getSelection();
                if (sel) {
                    const lines = sel.split('\n');
                    editor.replaceSelection(lines.map(l => `> ${l}`).join('\n'));
                } else {
                    const cursor = editor.getCursor();
                    editor.replaceRange('> ', cursor);
                }
                editor.focus();
                break;
            }
            case 'unordered-list': {
                const sel = editor.getSelection();
                if (sel) {
                    const lines = sel.split('\n');
                    editor.replaceSelection(lines.map(l => `- ${l}`).join('\n'));
                } else {
                    const cursor = editor.getCursor();
                    editor.replaceRange('- ', cursor);
                }
                editor.focus();
                break;
            }
            case 'ordered-list': {
                const sel = editor.getSelection();
                if (sel) {
                    const lines = sel.split('\n');
                    editor.replaceSelection(lines.map((l, i) => `${i + 1}. ${l}`).join('\n'));
                } else {
                    const cursor = editor.getCursor();
                    editor.replaceRange('1. ', cursor);
                }
                editor.focus();
                break;
            }
            case 'link': {
                const sel = editor.getSelection();
                if (sel) {
                    wrapText(editor, '[', '](url)');
                    const cursor = editor.getCursor();
                    editor.setCursor(cursor.line, cursor.ch - 1);
                } else {
                    const start = editor.getCursor();
                    wrapText(editor, '[', '](url)', 'text');
                    editor.setSelection({ line: start.line, ch: start.ch + 1 },
                                       { line: start.line, ch: start.ch + 5 });
                }
                break;
            }
            case 'image': {
                const sel = editor.getSelection();
                if (sel) {
                    wrapText(editor, '![' , '](url)');
                    const cursor = editor.getCursor();
                    editor.setCursor(cursor.line, cursor.ch - 1);
                } else {
                    const start = editor.getCursor();
                    wrapText(editor, '![' , '](url)', 'alt text');
                    editor.setSelection({ line: start.line, ch: start.ch + 2 },
                                       { line: start.line, ch: start.ch + 10 });
                }
                break;
            }
            case 'table':
                showTablePicker(button);
                break;
            case 'horizontal-rule': {
                const cursor = editor.getCursor();
                editor.replaceRange('\n---\n', cursor);
                editor.focus();
                break;
            }
            case 'recent-edits':
                addRecentEdits(editor);
                break;
            case 'total':
                addTotal(editor);
                break;
            case 'undo':
                editor.undo();
                editor.focus();
                break;
            case 'redo':
                editor.redo();
                editor.focus();
                break;
            case 'preview':
                togglePreview();
                break;
            case 'emoji':
                showEmojiPicker(button);
                break;
            case 'doc-link':
                showDocPicker(button);
                break;
            case 'anchor-link':
                showAnchorPicker(button);
                break;
            default:
                break;
        }
    };

    toolbar.addEventListener('click', (e) => {
        const btn = e.target.closest('button');
        if (!btn) return;
        const action = btn.dataset.action;
        if (action) exec(action, btn);
    });

    toolbar._delegateSetup = true;

    // Return here so the old individual listeners below will never execute
    return;
}

// Function to create statusbar
function createStatusbar(container) {
    const statusbar = document.createElement('div');
    statusbar.className = 'editor-statusbar';

    // Add status elements (lines, words, cursor position)
    const linesStatus = document.createElement('span');
    linesStatus.className = 'lines';
    linesStatus.textContent = '0';

    const wordsStatus = document.createElement('span');
    wordsStatus.className = 'words';
    wordsStatus.textContent = '0';

    const cursorStatus = document.createElement('span');
    cursorStatus.className = 'cursor';
    cursorStatus.textContent = '0:0';

    statusbar.appendChild(linesStatus);
    statusbar.appendChild(wordsStatus);
    statusbar.appendChild(cursorStatus);

    container.appendChild(statusbar);
    return statusbar;
}

// Function to update statusbar
function updateStatusbar(statusbar) {
    if (!editor || !statusbar) return;

    const content = editor.getValue();
    const lines = content.split('\n').length;
    const words = content.trim() ? content.trim().split(/\s+/).length : 0;
    const cursor = editor.getCursor();

    statusbar.querySelector('.lines').textContent = lines;
    statusbar.querySelector('.words').textContent = words;
    statusbar.querySelector('.cursor').textContent = `${cursor.line + 1}:${cursor.ch}`;
}

// Function to create preview panel
function createPreview(container) {
    const preview = document.createElement('div');
    preview.className = 'editor-preview';
    container.appendChild(preview);
    return preview;
}

// Function to toggle preview
async function togglePreview() {
    if (!editor || !previewElement) return;

    const isPreviewActive = previewElement.classList.contains('editor-preview-active');
    const editorElement = document.querySelector('.CodeMirror');
    const toolbar = document.querySelector('.custom-toolbar');

    if (isPreviewActive) {
        // Switch back to edit mode
        previewElement.classList.remove('editor-preview-active');

        // Show editor again
        if (editorElement) {
            editorElement.style.display = 'block';
        }

        // Re-enable all toolbar buttons except preview
        if (toolbar) {
            const buttons = toolbar.querySelectorAll('button:not(.preview-button)');
            buttons.forEach(button => {
                button.disabled = false;
                button.classList.remove('disabled');
            });
        }

        // Change preview button icon to indicate function
        const previewButton = toolbar.querySelector('.preview-button i');
        if (previewButton) {
            previewButton.className = 'fa fa-eye';
            previewButton.parentElement.title = 'Toggle Preview';
        }

        // Make sure editor gets focus when returning from preview mode
        // Using a small timeout to ensure DOM is updated first
        setTimeout(() => {
            if (editor) {
                editor.refresh();
                editor.focus();
            }
        }, 50);
    } else {
        // Show preview
        const content = editor.getValue();
        await updatePreview(content);

        // Hide editor
        if (editorElement) {
            editorElement.style.display = 'none';
        }

        // Show preview
        previewElement.classList.add('editor-preview-active');

        // Disable all toolbar buttons except preview
        if (toolbar) {
            const buttons = toolbar.querySelectorAll('button:not(.preview-button)');
            buttons.forEach(button => {
                button.disabled = true;
                button.classList.add('disabled');
            });
        }

        // Change preview button icon to indicate function
        const previewButton = toolbar.querySelector('.preview-button i');
        if (previewButton) {
            previewButton.className = 'fa fa-edit';
            previewButton.parentElement.title = 'Back to Edit Mode';
        }
    }
}

// Function to update preview content
async function updatePreview(content) {
    if (!previewElement) return;

    try {
        // Show loading indicator
        previewElement.innerHTML = '<div class="preview-loading">Loading preview...</div>';

        // Get current path for handling relative links correctly
        const isHomepage = window.location.pathname === '/';
        const path = isHomepage ? '/' : window.location.pathname;

        // Call the server-side renderer
        const response = await fetch(`/api/render-markdown?path=${encodeURIComponent(path)}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'text/plain',
            },
            body: content
        });

        if (!response.ok) {
            throw new Error('Failed to render markdown');
        }

        const html = await response.text();
        previewElement.innerHTML = html;

        // Initialize any client-side renderers (Prism, MathJax, etc)
        if (window.Prism) {
            Prism.highlightAllUnder(previewElement);
        }

        if (window.MathJax) {
            MathJax.typeset([previewElement]);
        }

        if (window.mermaid) {
            mermaid.init(undefined, previewElement.querySelectorAll('.mermaid'));
        }

    } catch (error) {
        console.error('Preview error:', error);
        previewElement.innerHTML = '<p>Error rendering preview</p>';
    }
}

// Main editor functions
async function loadEditor(mainContent, editorContainer, viewToolbar, editToolbar) {
    try {
        const isHomepage = window.location.pathname === '/';
        const apiPath = isHomepage ? '/api/source/' : `/api/source${window.location.pathname}`;

        const response = await fetch(apiPath);
        if (!response.ok) throw new Error('Failed to fetch content');

        const markdown = await response.text();

        // Show editor and switch toolbars
        mainContent.classList.add('editing');
        editorContainer.classList.add('active');
        viewToolbar.style.display = 'none';
        editToolbar.style.display = 'flex';

        // Clear the editor container
        editorContainer.innerHTML = '';

        // Create a container for our editor components (toolbar, editor, preview, statusbar)
        const editorLayout = document.createElement('div');
        editorLayout.className = 'editor-layout';
        editorContainer.appendChild(editorLayout);

        // 1. Create toolbar at the top
        const toolbar = createToolbar(editorLayout);

        // 2. Create an editor area container to hold both editor and preview
        const editorArea = document.createElement('div');
        editorArea.className = 'editor-area';
        editorLayout.appendChild(editorArea);

        // 3. Create editor wrapper inside the editor area
        const editorWrapper = document.createElement('div');
        editorWrapper.className = 'custom-editor-wrapper';
        editorArea.appendChild(editorWrapper);

        // 4. Create textarea for CodeMirror
        const textarea = document.createElement('textarea');
        textarea.id = 'markdown-editor';
        editorWrapper.appendChild(textarea);

        // 5. Create preview element inside the editor area
        previewElement = createPreview(editorArea);

        // 6. Create statusbar at the bottom
        const statusbar = createStatusbar(editorLayout);

        // Reset the preview mode
        previewElement.classList.remove('editor-preview-active');

        // Initialize CodeMirror
        if (!editor) {
            // Check if we're on mobile
            const isMobile = window.innerWidth <= 768;

            editor = CodeMirror.fromTextArea(textarea, {
                mode: 'markdown',
                theme: 'default', // Always use default theme and customize it
                lineNumbers: true,
                lineWrapping: true,
                autofocus: true,
                tabSize: 2,
                indentWithTabs: false,
                // Disable styleActiveLine completely on mobile to prevent the highlighting issue
                styleActiveLine: isMobile ? false : {
                    nonEmpty: true
                },
                extraKeys: {
                    "Enter": "newlineAndIndentContinueMarkdownList",
                    "Tab": (cm) => cm.execCommand("indentMore"),
                    "Shift-Tab": (cm) => cm.execCommand("indentLess"),
                    // Add keyboard shortcut for toggling preview
                    "Ctrl-P": togglePreview
                },
                placeholder: 'Write your markdown here...',
                spellcheck: true,
                gutters: ["CodeMirror-linenumbers"]
            });

            // Apply custom subtle styling to the editor
            const isDarkMode = document.documentElement.getAttribute('data-theme') === 'dark';

            // Apply custom styling to tone down the syntax highlighting colors
            const editorElement = document.querySelector('.CodeMirror');
            if (editorElement) {
                updateCodeMirrorTheme(isDarkMode ? 'dark' : 'light');
            }

            // Set editor height
            editor.setSize(null, "calc(100vh - 380px)");

            // Set up events for toolbar interactions
            setupToolbarActions(toolbar);

            // Set up events for statusbar updates
            editor.on('cursorActivity', () => updateStatusbar(statusbar));
            editor.on('change', () => {
                updateStatusbar(statusbar);

                // Update preview if active
                if (previewElement.classList.contains('editor-preview-active')) {
                    updatePreview(editor.getValue());
                }
            });
        }

        // Set initial content
        editor.setValue(markdown);

        // Make sure editor is visible (not in preview mode)
        document.querySelector('.CodeMirror').style.display = 'block';

        // Force a refresh with multiple attempts to ensure editor renders properly
        // This helps with keyboard shortcut entry reliability
        refreshEditor(statusbar);

    } catch (error) {
        console.error('Error:', error);
        alert('Failed to load content for editing');
    }
}

// Helper function to ensure editor gets properly refreshed
function refreshEditor(statusbar) {
    if (!editor) return;

    // Immediate refresh - apply all refreshes at once
    editor.refresh();
    editor.focus();
    if (statusbar) updateStatusbar(statusbar);

    // Secondary quick refresh to ensure rendering
    requestAnimationFrame(() => {
        if (editor) {
            editor.refresh();
            editor.focus();
            if (statusbar) updateStatusbar(statusbar);
        }
    });
}

function exitEditMode(mainContent, editorContainer, viewToolbar, editToolbar) {
    // Make sure to update UI state classes first
    if (mainContent) mainContent.classList.remove('editing');
    if (editorContainer) editorContainer.classList.remove('active');

    // Update toolbar visibility
    if (viewToolbar) viewToolbar.style.display = 'flex';
    if (editToolbar) editToolbar.style.display = 'none';

    // Completely destroy the editor instance
    if (editor) {
        try {
            editor.toTextArea();
        } catch(e) {
            console.warn('Error while destroying editor:', e);
        }
        editor = null;
    }

    // Remove preview element
    if (previewElement) {
        previewElement.remove();
        previewElement = null;
    }

    // Remove table picker if it exists
    if (tablePickerElement) {
        tablePickerElement.remove();
        tablePickerElement = null;
    }

    // Remove emoji picker if it exists
    if (emojiPickerElement) {
        emojiPickerElement.remove();
        emojiPickerElement = null;
    }
}

function getEditorContent() {
    return editor ? editor.getValue() : '';
}

function insertIntoEditor(url, isImage, name) {
    // Check if editor exists and is initialized
    if (!editor) {
        return false;
    }

    // Check if it's an MP4 file
    const isVideo = name.toLowerCase().endsWith('.mp4');

    // Extract just the filename from the URL
    const filename = name;

    // Create markdown code based on file type
    let markdown = '';
    if (isVideo) {
        // For MP4 files, use code block syntax with just the filename
        markdown = "```mp4\n" + filename + "\n```\n\n";
    } else if (isImage) {
        // For images, use image markdown with just the filename
        markdown = `![${name}](${filename})\n\n`;
    } else {
        // For other files, use link markdown with just the filename
        markdown = `[${name}](${filename})\n\n`;
    }

    // Insert markdown at cursor position
    editor.replaceSelection(markdown);

    // Focus the editor
    editor.focus();

    return true;
}

// Function to insert raw content into the editor
function insertRawContent(content) {
    // Check if editor exists and is initialized
    if (!editor) {
        return false;
    }

    // Insert content at cursor position
    editor.replaceSelection(content);

    // Focus the editor
    editor.focus();

    return true;
}

// Function to check if editor is active
function isEditorActive() {
    return !!editor;
}

// Export the functions
window.WikiEditor = {
    loadEditor,
    exitEditMode,
    getEditorContent,
    insertIntoEditor,
    insertRawContent,
    isEditorActive,
    // Adding functions for edit button and save button functionality
    initializeEditControls
};

// Function to initialize edit controls
function initializeEditControls() {
    const editPageButton = document.querySelector('.edit-page');
    const saveButton = document.querySelector('.save-changes');
    const cancelButton = document.querySelector('.cancel-edit');
    const mainContent = document.querySelector('.content');
    const editorContainer = document.querySelector('.editor-container');
    const viewToolbar = document.querySelector('.view-toolbar');
    const editToolbar = document.querySelector('.edit-toolbar');
    const markdownContent = document.querySelector('.markdown-content');

    // Auto-enter edit mode if content is empty
    if (markdownContent && editPageButton) {
        const contentText = markdownContent.textContent.trim();
        const h1Only = markdownContent.children.length === 1 &&
                      markdownContent.children[0].tagName === 'H1';

        if (h1Only) {
            editPageButton.click();
        }
    }

    // Update edit button functionality
    if (editPageButton) {
        editPageButton.addEventListener('click', async function() {
            try {
                // Check if user is authenticated
                const authResponse = await fetch('/api/check-auth');
                if (authResponse.status === 401) {
                    // Show login dialog
                    window.Auth.showLoginDialog(() => {
                        // After login, check if user has editor or admin role
                        window.Auth.checkUserRole('editor').then(canEdit => {
                            if (canEdit) {
                                loadEditor(mainContent, editorContainer, viewToolbar, editToolbar);
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
                    loadEditor(mainContent, editorContainer, viewToolbar, editToolbar);
                } else {
                    window.Auth.showPermissionError('editor');
                }
            } catch (error) {
                console.error('Error:', error);
                alert('Failed to check authentication status');
            }
        });
    }

    // Save button functionality
    if (saveButton) {
        saveButton.addEventListener('click', async function() {
            try {
                const isHomepage = window.location.pathname === '/';
                const apiPath = isHomepage ? '/api/save/' : `/api/save${window.location.pathname}`;

                const content = getEditorContent();

                const response = await fetch(apiPath, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'text/plain',
                    },
                    body: content
                });

                if (!response.ok) throw new Error('Failed to save content');

                window.location.reload();

            } catch (error) {
                console.error('Error:', error);
                alert('Failed to save changes');
            }
        });
    }

    // Cancel button functionality
    if (cancelButton) {
        cancelButton.addEventListener('click', function() {
            exitEditMode(mainContent, editorContainer, viewToolbar, editToolbar);
        });
    }
}

function ensureCMThemeLink() {
    return document.getElementById('cm-theme') ||
           Object.assign(document.head.appendChild(document.createElement('link')),
                         { id:'cm-theme', rel:'stylesheet' });
}

function updateCodeMirrorTheme(theme) {
    ensureCMThemeLink().href =
        (theme === 'dark' ? '/static/css/cm-dark.css' : '/static/css/cm-light.css');
}

updateCodeMirrorTheme(document.documentElement.getAttribute('data-theme'));
document.documentElement.addEventListener('data-theme-change', e =>
    updateCodeMirrorTheme(e.detail));

// Listen for theme changes and update the editor colors
const themeObserver = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
        if (mutation.attributeName === 'data-theme') {
            updateCodeMirrorTheme(mutation.newValue);
        }
    });
});

// Start observing theme changes
themeObserver.observe(document.documentElement, { attributes: true });

// Handle mobile sidebar state for editor
function setupMobileSidebarEffect() {
    // Only needed for mobile view
    if (window.innerWidth > 768) return;

    const hamburger = document.querySelector('.hamburger');
    const sidebar = document.querySelector('.sidebar');

    if (!hamburger || !sidebar) return;

    const handleSidebarToggle = () => {
        const isActive = sidebar.classList.contains('active');
        const editorContainer = document.querySelector('.editor-container');
        const editorLayout = document.querySelector('.editor-layout');
        const editorArea = document.querySelector('.editor-area');
        const previewElement = document.querySelector('.editor-preview');

        if (isActive && editorContainer) {
            // Ensure editor elements get sidebar-blur class when sidebar is open
            if (editor && document.body.classList.contains('sidebar-active')) {
                // Add sidebar-blur class to editor elements
                editorContainer.classList.add('sidebar-blur');
                if (editorLayout) editorLayout.classList.add('sidebar-blur');
                if (editorArea) editorArea.classList.add('sidebar-blur');
                if (previewElement) previewElement.classList.add('sidebar-blur');
            }
        } else {
            // Remove sidebar-blur class when sidebar is closed
            if (editorContainer) editorContainer.classList.remove('sidebar-blur');
            if (editorLayout) editorLayout.classList.remove('sidebar-blur');
            if (editorArea) editorArea.classList.remove('sidebar-blur');
            if (previewElement) previewElement.classList.remove('sidebar-blur');

            // Ensure editor gets focus back when needed
            if (editor && document.querySelector('.CodeMirror')) {
                setTimeout(() => {
                    editor.refresh();
                }, 300);
            }
        }
    };

    // Listen for sidebar toggle events
    hamburger.addEventListener('click', handleSidebarToggle);

    // Also observe body class changes to detect sidebar state
    const bodyObserver = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.attributeName === 'class') {
                if (document.body.classList.contains('sidebar-active')) {
                    // Sidebar is open
                    handleSidebarToggle();
                } else {
                    // Sidebar is closed
                    handleSidebarToggle();
                }
            }
        });
    });

    bodyObserver.observe(document.body, { attributes: true });
}

// Call this function when the page loads
document.addEventListener('DOMContentLoaded', setupMobileSidebarEffect);

// Also call when window resizes between mobile and desktop views
window.addEventListener('resize', () => {
    setupMobileSidebarEffect();

    // Adjust active line styling based on viewport width
    if (editor) {
        const isMobile = window.innerWidth <= 768;
        // Get the current editor options
        const editorOptions = editor.getOption('styleActiveLine');

        // Only change the option if it's different from the current setting
        if ((isMobile && editorOptions !== false) ||
            (!isMobile && JSON.stringify(editorOptions) !== JSON.stringify({nonEmpty: true}))) {

            editor.setOption('styleActiveLine', isMobile ? false : { nonEmpty: true });

            // Force a refresh to apply changes
            setTimeout(() => editor.refresh(), 10);
        }
    }
});

// Add dedicated ESC key handler for exiting edit mode
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        // Only handle if we're in edit mode and no dialogs are open
        const mainContent = document.querySelector('.content');
        const editorContainer = document.querySelector('.editor-container');
        const viewToolbar = document.querySelector('.view-toolbar');
        const editToolbar = document.querySelector('.edit-toolbar');

        if (mainContent && mainContent.classList.contains('editing')) {
            // Check if any dialogs are open - we shouldn't exit edit mode if dialogs are open
            const hasOpenDialog =
                document.querySelector('.version-history-dialog')?.classList.contains('active') ||
                document.querySelector('.file-upload-dialog')?.classList.contains('active') ||
                document.querySelector('.login-dialog')?.classList.contains('active') ||
                document.querySelector('.message-dialog')?.classList.contains('active') ||
                document.querySelector('.confirmation-dialog')?.classList.contains('active') ||
                document.querySelector('.user-confirmation-dialog')?.classList.contains('active') ||
                document.querySelector('.new-document-dialog')?.classList.contains('active') ||
                document.querySelector('.settings-dialog')?.classList.contains('active') ||
                document.querySelector('.move-document-dialog')?.classList.contains('active');

            if (!hasOpenDialog) {
                exitEditMode(mainContent, editorContainer, viewToolbar, editToolbar);
                e.preventDefault();
            }
        }
    }
});

// Preload emoji data when the page loads to avoid AJAX delay when editor is opened
document.addEventListener('DOMContentLoaded', function() {
    // Preload emoji data in the background - browsers will also preload it via Link header
    setTimeout(() => {
        EmojiCache.getData().then(() => {
            console.log('Emoji data preloaded successfully');
        });
    }, 1000); // Delay by 1 second to let page finish loading first
});

// Add helper to position picker elements based on real size instead of a hard-coded estimate
function positionPicker(picker, button) {
    // The picker must already be visible (display:block) before calling this
    const rect = button.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;

    const pickerWidth = picker.offsetWidth;
    const pickerHeight = picker.offsetHeight;

    // Initial position – directly under the button
    let left = rect.left;
    let top = rect.bottom;

    const isSmallScreen = viewportWidth < 500;

    if (isSmallScreen) {
        // Centre horizontally on very small screens
        left = Math.max(10, (viewportWidth - pickerWidth) / 2);
        // If the button sits in the lower half, place picker above it
        if (rect.bottom > viewportHeight / 2) {
            top = rect.top - pickerHeight - 5;
        }
    } else {
        // Ensure the picker does not overflow the right edge
        if (left + pickerWidth > viewportWidth - 10) {
            // Align the right edges of button and picker
            left = rect.right - pickerWidth;
            // Keep at least 10 px padding from the viewport's left side
            left = Math.max(10, left);
        }
        // Ensure the picker does not overflow the bottom edge
        if (top + pickerHeight > viewportHeight - 10) {
            // Place the picker above the button
            top = rect.top - pickerHeight - 5;
            // Keep at least 10 px from the top edge
            if (top < 10) {
                top = 10;
            }
        }
    }

    picker.style.left = `${left}px`;
    picker.style.top = `${top}px`;
}

// Generic helper to toggle pickers (emoji, table, doc, etc.)
function togglePicker({ get, set, create, button, closeSelector, onShow, onHide, beforeShow }) {
    let picker = get();

    // Lazily create picker if not existing
    if (!picker) {
        picker = create();
        if (typeof set === 'function') set(picker);
    }

    // If picker is currently visible, hide it and exit
    if (picker.style.display === 'block') {
        picker.style.display = 'none';
        picker.style.transform = '';
        if (picker._closeHandler) {
            document.removeEventListener('click', picker._closeHandler);
            picker._closeHandler = null;
        }
        if (typeof onHide === 'function') onHide(picker);
        return;
    }

    if (typeof beforeShow === 'function') beforeShow(picker);

    // Show the picker
    picker.style.display = 'block';

    // Position after it's visible
    requestAnimationFrame(() => {
        positionPicker(picker, button);
        setTimeout(() => positionPicker(picker, button), 50);
    });

    if (typeof onShow === 'function') onShow(picker);

    // Outside click handler
    const closeHandler = function(e) {
        if (!picker.contains(e.target) && !e.target.closest(closeSelector)) {
            picker.style.display = 'none';
            picker.style.transform = '';
            document.removeEventListener('click', closeHandler);
            picker._closeHandler = null;
            if (typeof onHide === 'function') onHide(picker);
        }
    };

    // Delay registration to avoid immediate close
    setTimeout(() => document.addEventListener('click', closeHandler), 0);
    picker._closeHandler = closeHandler;
}

// Function to slugify heading text (mirror of Go makeSlug)
function makeSlug(text) {
    return text.toLowerCase()
        .replace(/[&+_,.()\[\]{}'"!?;:~*]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .replace(/ /g, '-')
        .replace(/[^a-z0-9-]/g, '')
        .replace(/-+/g, '-')
        .replace(/^[-]+|[-]+$/g, '') || 'heading';
}

// Case-insensitive substring check
function includesIgnoreCase(value = '', query = '') {
    return value.toLowerCase().includes((query || '').toLowerCase());
}

// Factory that returns a button element (used by both doc-link and anchor pickers)
function createDocButton(doc, onSelect) {
    const btn = document.createElement('button');
    btn.className = 'doc-btn';
    btn.title = doc.path;
    btn.style.boxSizing = 'border-box';
    btn.style.width = '100%';

    const docName = document.createElement('div');
    docName.className = 'doc-name';
    docName.textContent = doc.title || doc.path.split('/').pop();

    const docPath = document.createElement('div');
    docPath.className = 'doc-path';
    docPath.textContent = doc.path;

    btn.appendChild(docName);
    btn.appendChild(docPath);

    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (typeof onSelect === 'function') onSelect();
    });

    return btn;
}

// Extract headings and IDs from current editor content
function extractAnchors(markdown) {
    const lines = markdown.split('\n');
    const headingRx = /^(#{1,6})\s+(.*?)\s*(\{#([a-zA-Z0-9\-]+)\})?\s*$/;
    const anchors = [];
    const usedIds = {};

    let inCodeBlock = false;

    lines.forEach((ln) => {
        const trimmed = ln.trim();

        // Toggle code block state on fences ``` or ~~~
        if (trimmed.startsWith('```') || trimmed.startsWith('~~~')) {
            inCodeBlock = !inCodeBlock;
            return;
        }
        if (inCodeBlock) return; // Skip lines inside fenced code blocks

        const m = trimmed.match(headingRx);
        if (!m) return;
        const level = m[1].length;
        const text = m[2].trim();
        let id = m[4] || makeSlug(text);
        if (!id) id = "heading";

        // Ensure uniqueness (mirror Go logic)
        if (usedIds[id]) {
            let counter = 1;
            let newId;
            do {
                newId = `${id}-${counter}`;
                counter++;
            } while (usedIds[newId]);
            id = newId;
        }
        usedIds[id] = true;

        anchors.push({ level, text, id });
    });

    return anchors;
}

// Insert anchor link in markdown
function insertAnchorLink(anchor) {
    if (!editor) return;

    const selection = editor.getSelection();
    const linkText = selection || anchor.text;

    if (selection) {
        editor.replaceSelection(`[${selection}](#${anchor.id})`);
    } else {
        const cursor = editor.getCursor();
        editor.replaceRange(`[${linkText}](#${anchor.id})`, cursor);
        // Select link text for editing if no selection existed
        editor.setSelection(
            { line: cursor.line, ch: cursor.ch + 1 },
            { line: cursor.line, ch: cursor.ch + 1 + linkText.length }
        );
    }

    editor.focus();
}

// Helper: fetch raw markdown for a document path
async function fetchDocumentSource(docPath) {
    try {
        const response = await fetch(`/api/source${docPath}`);
        if (!response.ok) throw new Error('Failed to fetch document');
        return await response.text();
    } catch (err) {
        console.error('fetchDocumentSource', err);
        throw err;
    }
}

// Insert link to an anchor that belongs to another document
function insertDocAnchorLink(document, anchor) {
    if (!editor) return;

    // Prepare path (mirror insertDocLink logic)
    let path = document.path;
    if (path.startsWith('/documents')) {
        path = path.replace('/documents', '');
    }

    const selection = editor.getSelection();
    const linkText = selection || anchor.text;
    const markdown = `[${linkText}](${path}#${anchor.id})`;

    if (selection) {
        editor.replaceSelection(markdown);
    } else {
        const cursor = editor.getCursor();
        editor.replaceRange(markdown, cursor);
        editor.setSelection(
            { line: cursor.line, ch: cursor.ch + 1 },
            { line: cursor.line, ch: cursor.ch + 1 + linkText.length }
        );
    }

    editor.focus();
}

// Create a picker that first lists documents and then their anchors
function createDocAnchorPicker() {
    const picker = document.createElement('div');
    picker.className = 'anchor-picker';
    picker.style.display = 'none';
    picker.setAttribute('dir', 'auto');

    // Header (title + back button)
    const header = document.createElement('div');
    header.className = 'anchor-picker-header';
    picker.appendChild(header);

    const backBtn = document.createElement('button');
    backBtn.className = 'anchor-back-btn';
    backBtn.textContent = '←';
    backBtn.style.display = 'none';
    header.appendChild(backBtn);

    const titleEl = document.createElement('span');
    titleEl.className = 'anchor-picker-title';
    titleEl.textContent = '';
    header.appendChild(titleEl);

    // Search input
    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.className = 'anchor-search-input';
    searchInput.placeholder = window.i18n ? window.i18n.t('docpicker.search_placeholder') : 'Search…';
    picker.appendChild(searchInput);

    // Container for list items
    const listContainer = document.createElement('div');
    listContainer.className = 'anchor-list-container';
    picker.appendChild(listContainer);

    document.body.appendChild(picker);

    // State variables
    let currentDocument = null;
    const anchorsCache = {}; // path -> anchors array
    let docs = [];

    const renderNoResults = (msg) => {
        listContainer.innerHTML = '';
        const noRes = document.createElement('div');
        noRes.className = 'no-results';
        noRes.textContent = window.i18n ? window.i18n.t(msg) || msg : msg;
        listContainer.appendChild(noRes);
    };

    const filterString = (value, query) => value.toLowerCase().includes(query.toLowerCase());

    // Render document list
    const renderDocList = (query = '') => {
        currentDocument = null;
        backBtn.style.display = 'none';
        titleEl.textContent = '';
        listContainer.innerHTML = '';
        // Reset search field & placeholder for document mode if coming from anchor mode
        searchInput.placeholder = 'Search document…';

        if (currentDocument !== null) {
            // ensure query retains but if currentDocument is null we keep existing query; else we may keep previous search.
        }

        const filtered = query ? docs.filter(doc =>
            includesIgnoreCase(doc.title || '', query) || includesIgnoreCase(doc.path, query))
            : docs;

        if (filtered.length === 0) {
            renderNoResults('docpicker.no_results');
            return;
        }

        filtered.forEach(doc => {
            const btn = createDocButton(doc, async () => {
                try {
                    let anchors = anchorsCache[doc.path];
                    if (!anchors) {
                        const md = await fetchDocumentSource(doc.path);
                        anchors = extractAnchors(md);
                        anchorsCache[doc.path] = anchors;
                    }
                    renderAnchorList(doc, anchors);
                } catch (err) {
                    console.error(err);
                    renderNoResults('Failed to load headings');
                }
            });
            listContainer.appendChild(btn);
        });
    };

    // Render anchor list for a selected document
    const renderAnchorList = (doc, anchors, query = '') => {
        currentDocument = doc;
        backBtn.style.display = 'inline-block';
        titleEl.textContent = doc.title || doc.path;
        listContainer.innerHTML = '';
        // Switch placeholder to heading search and clear existing text (optional)
        searchInput.placeholder = 'Search heading…';

        const filteredAnchors = query ? anchors.filter(a =>
            includesIgnoreCase(a.text, query) || includesIgnoreCase(a.id, query))
            : anchors;

        if (filteredAnchors.length === 0) {
            renderNoResults('No headings found');
            return;
        }

        filteredAnchors.forEach(a => {
            const btn = document.createElement('button');
            btn.className = `anchor-btn level-${a.level}`;
            btn.textContent = `${'  '.repeat(a.level - 1)}${a.text}`;
            btn.title = `#${a.id}`;
            btn.addEventListener('click', (ev) => {
                ev.stopPropagation();
                insertDocAnchorLink(doc, a);
                hideAnchorPicker();
            });
            listContainer.appendChild(btn);
        });
    };

    // Back button behavior
    backBtn.addEventListener('click', () => {
        searchInput.value = '';
        renderDocList();
    });

    // Search handler
    searchInput.addEventListener('input', (e) => {
        const query = e.target.value;
        if (currentDocument) {
            const anchors = anchorsCache[currentDocument.path] || [];
            renderAnchorList(currentDocument, anchors, query);
        } else {
            renderDocList(query);
        }
    });

    // Initial fetch of documents (reuse global cache if available)
    (async () => {
        try {
            docs = documentData.length ? documentData : await fetchDocuments();
            renderDocList();
        } catch (err) {
            renderNoResults(err.message || window.i18n ? window.i18n.t('docpicker.error_loading') : 'Error loading documents');
        }
    })();

    // Expose refresh method for showAnchorPicker()
    picker.renderList = () => {
        if (currentDocument) {
            const anchors = anchorsCache[currentDocument.path] || [];
            renderAnchorList(currentDocument, anchors, searchInput.value || '');
        } else {
            renderDocList(searchInput.value || '');
        }
    };

    // Expose a reset method so the caller can force picker to start at doc list
    picker.resetView = () => {
        searchInput.value = '';
        renderDocList();
    };

    return picker;
}

// Modify showAnchorPicker to use the new picker
function showAnchorPicker(button) {
    if (!anchorPickerElement) {
        anchorPickerElement = createDocAnchorPicker();
    }

    // Always reset to the top-level document list before showing
    if (typeof anchorPickerElement.resetView === 'function') {
        anchorPickerElement.resetView();
    }

    if (anchorPickerElement.style.display === 'block') {
        hideAnchorPicker();
        return;
    }

    // Refresh headings list each time the picker is shown to capture any new headings
    if (typeof anchorPickerElement.renderList === 'function') {
        const queryInput = anchorPickerElement.querySelector('.anchor-search-input');
        const currentQuery = queryInput ? queryInput.value : '';
        anchorPickerElement.renderList(currentQuery);
    }

    anchorPickerElement.style.display = 'block';
    requestAnimationFrame(() => {
        positionPicker(anchorPickerElement, button);
        setTimeout(() => positionPicker(anchorPickerElement, button), 50);
    });

    setTimeout(() => {
        const input = anchorPickerElement.querySelector('.anchor-search-input');
        if (input) input.focus();
    }, 50);

    const closeHandler = function(e) {
        if (!anchorPickerElement.contains(e.target) &&
            !e.target.closest('.anchor-link-button')) {
            hideAnchorPicker();
        }
    };

    // Store and register the handler so it can be cleaned up later
    anchorPickerElement._closeHandler = closeHandler;
    setTimeout(() => document.addEventListener('click', closeHandler), 0);
}

function hideAnchorPicker() {
    if (anchorPickerElement) {
        anchorPickerElement.style.display = 'none';

        // Clean up any outstanding outside-click listener
        if (anchorPickerElement._closeHandler) {
            document.removeEventListener('click', anchorPickerElement._closeHandler);
            anchorPickerElement._closeHandler = null;
        }
    }
}
