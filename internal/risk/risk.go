package risk

import "strings"

// Icon returns a colored emoji circle for the risk level.
func Icon(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

// DiscordColor returns a Discord embed color int for the risk level.
func DiscordColor(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 0xFF0000 // Red
	case "high":
		return 0xFF8C00 // Orange
	case "medium":
		return 0xFFD700 // Yellow
	case "low":
		return 0x00FF00 // Green
	default:
		return 0x808080 // Gray
	}
}
