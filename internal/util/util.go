package util

import "unicode/utf8"

// Truncate shortens s to maxLen runes, appending "..." if truncated.
// Safe for multi-byte UTF-8 strings (won't split codepoints).
func Truncate(s string, maxLen int) string {
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxLen-3]) + "..."
}
