package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

// Config holds all application configuration.
type Config struct {
	ShodanAPIKey      string
	MinimaxAPIKey     string
	DiscordWebhookURL string
}

// Load reads configuration from environment variables and optional .env file.
func Load() (*Config, error) {
	// Attempt to load .env file (ignore error if missing)
	_ = godotenv.Load()

	cfg := &Config{
		ShodanAPIKey:      os.Getenv("SHODAN_API_KEY"),
		MinimaxAPIKey:     os.Getenv("MINIMAX_API_KEY"),
		DiscordWebhookURL: os.Getenv("DISCORD_WEBHOOK_URL"),
	}

	if cfg.ShodanAPIKey == "" {
		return nil, fmt.Errorf("SHODAN_API_KEY is required — set it in your environment or .env file")
	}

	return cfg, nil
}

// ValidateMinimaxKey checks that the Minimax key is set (only needed when AI analysis is enabled).
func (c *Config) ValidateMinimaxKey() error {
	if c.MinimaxAPIKey == "" {
		return fmt.Errorf("MINIMAX_API_KEY is required for AI analysis — set it in your environment or .env file, or use --no-ai to skip")
	}
	return nil
}
