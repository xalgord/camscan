package minimax

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/camscan/internal/util"
)

const (
	apiURL     = "https://api.minimax.io/v1/chat/completions"
	model      = "MiniMax-M2.7"
	maxRetries = 3
)

// Client wraps the Minimax chat completions API.
type Client struct {
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new Minimax API client.
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 90 * time.Second,
		},
	}
}

const systemPrompt = `You are an expert cybersecurity analyst specializing in IoT and IP camera security.

You will receive banner data and metadata from an IP camera discovered via Shodan. Your task is to analyze this data and provide a security assessment.

You MUST respond with ONLY a valid JSON object (no markdown, no code fences, no explanation) in this exact format:
{
  "risk_level": "Critical|High|Medium|Low",
  "is_open": true/false,
  "default_creds": true/false,
  "vulnerabilities": ["list of identified vulnerabilities"],
  "recommendations": ["list of security recommendations"],
  "summary": "one-line summary of the security posture"
}

Assessment criteria:
- risk_level "Critical": No authentication, open stream, or known critical CVEs
- risk_level "High": Default credentials likely, outdated firmware, or exposed admin panel
- risk_level "Medium": Some security measures but with weaknesses (e.g., HTTP only, no TLS)
- risk_level "Low": Proper authentication, TLS enabled, updated firmware

Analyze the following indicators:
1. Is authentication required or is the stream/panel openly accessible?
2. Are default credentials likely in use (based on banner, product, HTTP title)?
3. Is the connection encrypted (TLS/SSL)?
4. Is the firmware/software version outdated or known-vulnerable?
5. Are there any known CVEs for this product/version?
6. Is the admin panel exposed to the internet?

Be specific in your vulnerability findings based on the actual banner data provided.`

// AnalyzeCamera sends camera data to Minimax M2.7 for security analysis.
// W3: Retries with exponential backoff on 429 rate-limit responses.
func (c *Client) AnalyzeCamera(ctx context.Context, cameraData string) (*SecurityAssessment, error) {
	reqBody := ChatRequest{
		Model: model,
		Messages: []Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: cameraData},
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 2s, 4s, 8s
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.apiKey)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("minimax API request failed: %w", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("failed to read response: %w", err)
			continue
		}

		// W3: Retry on 429 rate limit
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := resp.Header.Get("Retry-After")
			if secs, parseErr := strconv.Atoi(retryAfter); parseErr == nil && secs > 0 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(time.Duration(secs) * time.Second):
				}
			}
			lastErr = fmt.Errorf("minimax rate limited (attempt %d/%d)", attempt+1, maxRetries+1)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("minimax API error (HTTP %d): %s", resp.StatusCode, string(body))
		}

		return c.parseResponse(body)
	}

	return nil, fmt.Errorf("minimax API exhausted retries: %w", lastErr)
}

// parseResponse extracts the SecurityAssessment from a raw API response.
func (c *Client) parseResponse(body []byte) (*SecurityAssessment, error) {
	var chatResp ChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return nil, fmt.Errorf("failed to parse minimax response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("minimax returned no choices")
	}

	content := chatResp.Choices[0].Message.Content
	content = strings.TrimSpace(content)

	// Strip <think>...</think> reasoning tags (M2.7 includes these)
	if idx := strings.Index(content, "</think>"); idx != -1 {
		content = strings.TrimSpace(content[idx+len("</think>"):])
	} else if strings.HasPrefix(content, "<think>") {
		if jsonStart := strings.Index(content, "{"); jsonStart != -1 {
			content = content[jsonStart:]
		}
	}

	// Strip markdown code fences if present
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	// I4: Robust JSON extraction — find first '{' and last '}'
	jsonContent := extractJSON(content)

	var assessment SecurityAssessment
	if err := json.Unmarshal([]byte(jsonContent), &assessment); err != nil {
		// B4: Fallback uses "Unknown" instead of misleading "Medium"
		assessment = SecurityAssessment{
			RiskLevel:       "Unknown",
			IsOpen:          false,
			DefaultCreds:    false,
			Vulnerabilities: []string{"Unable to parse structured assessment"},
			Recommendations: []string{"Manual review recommended"},
			Summary:         util.Truncate(content, 100),
		}
	}

	return &assessment, nil
}

// extractJSON finds the outermost JSON object in the string.
func extractJSON(s string) string {
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start != -1 && end != -1 && end > start {
		return s[start : end+1]
	}
	return s
}
