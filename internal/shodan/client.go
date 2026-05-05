package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const baseURL = "https://api.shodan.io"

// Client wraps the Shodan REST API.
type Client struct {
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new Shodan API client.
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SearchQuery holds user-provided search parameters.
type SearchQuery struct {
	CameraType string // e.g. "webcam", "hikvision", "dahua"
	Country    string // 2-letter code
	State      string // region/state name
	City       string // city name
}

// BuildQuery constructs a Shodan search query string from the parameters.
func (q *SearchQuery) BuildQuery() string {
	var parts []string

	// Camera type / product search
	switch strings.ToLower(q.CameraType) {
	case "hikvision":
		parts = append(parts, `product:"Hikvision IP Camera"`)
	case "dahua":
		parts = append(parts, `product:"Dahua"`)
	case "axis":
		parts = append(parts, `product:"AXIS"`)
	case "rtsp":
		parts = append(parts, `"RTSP/1.0 200 OK"`)
	case "webcamxp":
		parts = append(parts, `server:"webcamXP"`)
	case "yawcam":
		parts = append(parts, `product:"Yawcam"`)
	case "blueiris":
		parts = append(parts, `title:"Blue Iris"`)
	case "all":
		// Broad search across multiple camera types
		parts = append(parts, `(product:"webcam" OR title:"IP Camera" OR "RTSP/1.0" OR product:"Hikvision" OR product:"Dahua" OR product:"AXIS" OR server:"webcamXP")`)
	default:
		// Default: generic webcam search
		parts = append(parts, `webcam`)
	}

	// Location filters
	if q.Country != "" {
		parts = append(parts, fmt.Sprintf("country:%s", strings.ToUpper(q.Country)))
	}
	if q.State != "" {
		parts = append(parts, fmt.Sprintf("state:\"%s\"", q.State))
	}
	if q.City != "" {
		parts = append(parts, fmt.Sprintf("city:\"%s\"", q.City))
	}

	return strings.Join(parts, " ")
}

// Search performs a host search on Shodan and returns discovered cameras.
func (c *Client) Search(ctx context.Context, query *SearchQuery, limit int) (*SearchResult, error) {
	q := query.BuildQuery()

	// Build request URL (B6: handle parse error)
	u, err := url.Parse(baseURL + "/shodan/host/search")
	if err != nil {
		return nil, fmt.Errorf("failed to parse Shodan URL: %w", err)
	}
	params := url.Values{}
	params.Set("key", c.apiKey)
	params.Set("query", q)
	params.Set("minify", "false") // Get full banner data
	u.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shodan API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan API error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var result SearchResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse shodan response: %w", err)
	}

	// Trim results to the requested limit
	if limit > 0 && len(result.Matches) > limit {
		result.Matches = result.Matches[:limit]
	}

	return &result, nil
}

// APIInfo holds Shodan API account information.
type APIInfo struct {
	QueryCredits int    `json:"query_credits"`
	ScanCredits  int    `json:"scan_credits"`
	Plan         string `json:"plan"`
}

// GetAPIInfo returns info about the API key (credits remaining, plan, etc.)
// B2: Uses url.Values to avoid leaking the API key in URL strings.
func (c *Client) GetAPIInfo(ctx context.Context) (*APIInfo, error) {
	u, err := url.Parse(baseURL + "/api-info")
	if err != nil {
		return nil, fmt.Errorf("failed to parse Shodan URL: %w", err)
	}
	params := url.Values{}
	params.Set("key", c.apiKey)
	u.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get API info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan API error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var info APIInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return &info, nil
}
