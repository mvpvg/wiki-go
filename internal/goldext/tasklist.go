package goldext

import (
	"regexp"
	"strconv"
	"strings"
)

// TaskListPreprocessor transforms markdown task list syntax directly to HTML
// This preprocessor runs before Goldmark rendering to ensure consistent styling
func TaskListPreprocessor(markdown string, _ string) string {
	// Process the document line by line
	lines := strings.Split(markdown, "\n")
	var result []string

	// Track processing state
	inCodeBlock := false
	listIndentations := make(map[int]string)

	for i, line := range lines {
		// Skip processing inside code blocks
		if strings.HasPrefix(strings.TrimSpace(line), "```") || strings.HasPrefix(strings.TrimSpace(line), "~~~") {
			inCodeBlock = !inCodeBlock
			result = append(result, line)
			continue
		}

		if inCodeBlock {
			result = append(result, line)
			continue
		}

		// Check if this is a list item with a task
		trimmedLine := strings.TrimSpace(line)
		indent := line[:len(line)-len(trimmedLine)]

		// Check for task list patterns
		uncheckedTask := regexp.MustCompile(`^([-*+])\s+\[\s*\]\s+(.*)$`).FindStringSubmatch(trimmedLine)
		checkedTask := regexp.MustCompile(`^([-*+])\s+\[(x|X)\]\s+(.*)$`).FindStringSubmatch(trimmedLine)

		// If this is a task list item, transform it to HTML
		if len(uncheckedTask) > 0 || len(checkedTask) > 0 {
			// Calculate the indentation level
			indentLevel := len(indent) / 2
			if indentLevel == 0 && len(indent) > 0 {
				indentLevel = 1 // Handle tab indentation
			}

			// Store indentation for this level
			listIndentations[i] = indent

			var taskText string
			isChecked := false

			if len(uncheckedTask) > 0 {
				taskText = uncheckedTask[2]
			} else {
				taskText = checkedTask[3]
				isChecked = true
			}

			// Pre-process task text
			processedTaskText := processTaskTextMarkdown(taskText)

			// Generate the HTML for this task list item
			var htmlLine string

			// Create the checkbox with proper classes and checked state
			checkbox := `<input type="checkbox" class="task-checkbox"`
			if isChecked {
				checkbox += ` checked`
			}
			checkbox += ` disabled>`

			// Add the indent level attribute for CSS styling
			indentAttr := ""
			if indentLevel > 0 {
				indentAttr = ` data-indent-level="` + strconv.Itoa(indentLevel) + `"`
			}

			// Preserve the original indentation in the output to maintain list structure
			htmlLine = indent + `<li class="task-list-item-container" style="list-style-type: none;"` + indentAttr +
				`><span class="task-list-item">` + checkbox + ` <span class="task-text">` + processedTaskText +
				`</span></span></li>`

			result = append(result, htmlLine)
		} else {
			// Not a task list item, pass through unchanged
			result = append(result, line)
		}
	}

	return strings.Join(result, "\n")
}

// Process task text to handle markdown formatting
func processTaskTextMarkdown(text string) string {
	// Process bold text (**text** or __text__)
	boldPattern := regexp.MustCompile(`(\*\*|__)([^*_]+)(\*\*|__)`)
	text = boldPattern.ReplaceAllString(text, "<strong>$2</strong>")

	// Process italic text (*text* or _text_)
	italicPattern := regexp.MustCompile(`(\*|_)([^*_]+)(\*|_)`)
	text = italicPattern.ReplaceAllString(text, "<em>$2</em>")

	// Process links [text](url)
	linkPattern := regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	text = linkPattern.ReplaceAllString(text, `<a href="$2">$1</a>`)

	// Process inline code (`code`)
	codePattern := regexp.MustCompile("`([^`]+)`")
	text = codePattern.ReplaceAllString(text, "<code>$1</code>")

	return text
}
