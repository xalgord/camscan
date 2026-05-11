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

	// Camera type / product search — targeting CCTV and IP surveillance cameras
	switch strings.ToLower(q.CameraType) {
	case "hikvision":
		parts = append(parts, `product:"Hikvision IP Camera"`)
	case "dahua":
		parts = append(parts, `product:"Dahua"`)
	case "huawei":
		parts = append(parts, `product:"Huawei"`)
	case "tiandy":
		parts = append(parts, `product:"Tiandy"`)
	case "axis":
		parts = append(parts, `product:"AXIS"`)
	case "rtsp":
		parts = append(parts, `"RTSP/1.0 200 OK"`)
	case "dvr":
		parts = append(parts, `http.title:"DVR"`)
	case "nvr":
		parts = append(parts, `http.title:"NVR"`)
	case "webcamxp":
		parts = append(parts, `server:"webcamXP"`)
	case "yawcam":
		parts = append(parts, `product:"Yawcam"`)
	case "blueiris":
		parts = append(parts, `title:"Blue Iris"`)
	case "avtech":
		parts = append(parts, `product:"AVTech"`)
	case "geovision":
		parts = append(parts, `title:"GeoVision"`)
	case "all":
		// Broad CCTV search — Shodan doesn't support OR, so use a generic title match
		// that catches the widest range of camera web interfaces
		parts = append(parts, `title:"camera"`)
	default:
		// Default: broad IP camera search using title filter
		parts = append(parts, `title:"camera"`)
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

// SearchRaw performs a Shodan search with a raw query string (no BuildQuery).
// Used by the AI query generator and the --query flag.
func (c *Client) SearchRaw(ctx context.Context, rawQuery string, limit int) (*SearchResult, error) {
	u, err := url.Parse(baseURL + "/shodan/host/search")
	if err != nil {
		return nil, fmt.Errorf("failed to parse Shodan URL: %w", err)
	}
	params := url.Values{}
	params.Set("key", c.apiKey)
	params.Set("query", rawQuery)
	params.Set("minify", "false")
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

	if limit > 0 && len(result.Matches) > limit {
		result.Matches = result.Matches[:limit]
	}

	return &result, nil
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
