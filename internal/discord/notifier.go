package discord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/camscan/internal/risk"
)

// Embed represents a Discord embed object.
type Embed struct {
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Color       int     `json:"color"`
	Fields      []Field `json:"fields"`
	Footer      *Footer `json:"footer,omitempty"`
	Timestamp   string  `json:"timestamp,omitempty"`
}

// Field is an embed field.
type Field struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// Footer is the embed footer.
type Footer struct {
	Text string `json:"text"`
}

type webhookPayload struct {
	Username string  `json:"username,omitempty"`
	Content  string  `json:"content,omitempty"`
	Embeds   []Embed `json:"embeds"`
}

// Notifier sends alerts to a Discord webhook.
type Notifier struct {
	webhookURL string
	httpClient *http.Client
}

// NewNotifier creates a new Discord webhook notifier.
func NewNotifier(webhookURL string) *Notifier {
	return &Notifier{
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// CameraAlert holds the data needed to send a camera alert.
type CameraAlert struct {
	IP                 string
	Port               int
	Product            string
	Location           string
	Org                string
	RiskLevel          string
	RiskScore          int
	IsOpen             bool
	DefaultCreds       bool
	Summary            string
	Vulnerabilities    []string // Flat titles from SecurityAssessment.VulnTitles()
	ExploitPaths       []string
	CveReferences      []string
	AccessInstructions []string
}

// SendAlert sends a rich embed notification for an open/critical camera.
// W4: Retries on HTTP 429 with Retry-After header. Retries up to 3 times.
func (n *Notifier) SendAlert(alert CameraAlert) error {
	color := risk.DiscordColor(alert.RiskLevel)

	vulns := "None identified"
	if len(alert.Vulnerabilities) > 0 {
		max := len(alert.Vulnerabilities)
		if max > 5 {
			max = 5
		}
		var items []string
		for _, v := range alert.Vulnerabilities[:max] {
			items = append(items, "• "+v)
		}
		vulns = strings.Join(items, "\n")
		if len(alert.Vulnerabilities) > 5 {
			vulns += fmt.Sprintf("\n... and %d more", len(alert.Vulnerabilities)-5)
		}
	}

	openStatus := "❌ No"
	if alert.IsOpen {
		openStatus = "✅ Yes — No Authentication"
	}

	credsStatus := "❌ No"
	if alert.DefaultCreds {
		credsStatus = "⚠️ Yes — Likely Default Credentials"
	}

	product := alert.Product
	if product == "" {
		product = "Unknown"
	}

	embed := Embed{
		Title:       fmt.Sprintf("🚨 Open Camera Found: %s:%d", alert.IP, alert.Port),
		Description: alert.Summary,
		Color:       color,
		Fields: []Field{
			{Name: "🌐 IP Address", Value: fmt.Sprintf("`%s:%d`", alert.IP, alert.Port), Inline: true},
			{Name: "📷 Product", Value: product, Inline: true},
			{Name: "📍 Location", Value: alert.Location, Inline: true},
			{Name: "🏢 Organization", Value: alert.Org, Inline: true},
			{Name: "⚡ Risk Level", Value: fmt.Sprintf("%s %s (%d/100)", risk.Icon(alert.RiskLevel), alert.RiskLevel, alert.RiskScore), Inline: true},
			{Name: "🔓 Open Access", Value: openStatus, Inline: true},
			{Name: "🔑 Default Creds", Value: credsStatus, Inline: false},
			{Name: "🛡️ Vulnerabilities", Value: vulns, Inline: false},
		},
		Footer:    &Footer{Text: "CamScan • Shodan + Minimax M2.7"},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Add exploit paths if present
	if len(alert.ExploitPaths) > 0 {
		max := len(alert.ExploitPaths)
		if max > 3 {
			max = 3
		}
		var paths []string
		for _, p := range alert.ExploitPaths[:max] {
			paths = append(paths, "⚔️ "+p)
		}
		embed.Fields = append(embed.Fields, Field{Name: "🎯 Exploit Paths", Value: strings.Join(paths, "\n"), Inline: false})
	}

	// Add CVE references if present
	if len(alert.CveReferences) > 0 {
		var cves []string
		for _, c := range alert.CveReferences {
			cves = append(cves, fmt.Sprintf("[%s](https://nvd.nist.gov/vuln/detail/%s)", c, c))
		}
		embed.Fields = append(embed.Fields, Field{Name: "📋 CVE References", Value: strings.Join(cves, " • "), Inline: false})
	}

	// Add access instructions if present
	if len(alert.AccessInstructions) > 0 {
		max := len(alert.AccessInstructions)
		if max > 4 {
			max = 4
		}
		var steps []string
		for i, inst := range alert.AccessInstructions[:max] {
			steps = append(steps, fmt.Sprintf("%d. %s", i+1, inst))
		}
		embed.Fields = append(embed.Fields, Field{Name: "🧭 How to Access", Value: strings.Join(steps, "\n"), Inline: false})
	}

	payload := webhookPayload{
		Username: "CamScan",
		Embeds:   []Embed{embed},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	// W4: Retry loop for Discord rate limits
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := n.httpClient.Post(n.webhookURL, "application/json", bytes.NewBuffer(body))
		if err != nil {
			return fmt.Errorf("failed to send webhook: %w", err)
		}

		// B3: Read the response body for error diagnostics
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil // Success
		}

		// W4: Handle 429 rate limit with Retry-After
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := resp.Header.Get("Retry-After")
			wait := 5 * time.Second // default wait
			if secs, parseErr := strconv.Atoi(retryAfter); parseErr == nil && secs > 0 {
				wait = time.Duration(secs) * time.Second
			}
			time.Sleep(wait)
			continue
		}

		// B3: Include response body in error message
		return fmt.Errorf("discord webhook returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return fmt.Errorf("discord webhook rate limited after 3 retries")
}

// ScanSummary holds data for the scan-completion notification.
type ScanSummary struct {
	Query        string
	TotalShodan  int
	Scanned      int
	Alerted      int
	Critical     int
	High         int
	Medium       int
	Low          int
	Unknown      int
	Errors       int
	Duration     time.Duration
}

// SendScanSummary sends a scan-completion embed to Discord.
func (n *Notifier) SendScanSummary(s ScanSummary) error {
	// Choose embed color based on worst finding
	embedColor := 0x2ECC71 // green — clean scan
	if s.Critical > 0 {
		embedColor = 0xE74C3C // red
	} else if s.High > 0 {
		embedColor = 0xF39C12 // orange
	} else if s.Medium > 0 {
		embedColor = 0xF1C40F // yellow
	}

	riskBreakdown := fmt.Sprintf(
		"🔴 Critical: **%d** │ 🟠 High: **%d** │ 🟡 Medium: **%d** │ 🟢 Low: **%d**",
		s.Critical, s.High, s.Medium, s.Low,
	)
	if s.Unknown > 0 {
		riskBreakdown += fmt.Sprintf(" │ ⚪ Unknown: **%d**", s.Unknown)
	}

	fields := []Field{
		{Name: "🔎 Query", Value: fmt.Sprintf("`%s`", s.Query), Inline: false},
		{Name: "📊 Risk Breakdown", Value: riskBreakdown, Inline: false},
		{Name: "📷 Cameras Scanned", Value: fmt.Sprintf("%d", s.Scanned), Inline: true},
		{Name: "🌐 Total in Shodan", Value: fmt.Sprintf("%d", s.TotalShodan), Inline: true},
		{Name: "🔔 Alerts Sent", Value: fmt.Sprintf("%d", s.Alerted), Inline: true},
		{Name: "⏱️ Duration", Value: s.Duration.Truncate(time.Second).String(), Inline: true},
	}

	if s.Errors > 0 {
		fields = append(fields, Field{Name: "❌ Analysis Errors", Value: fmt.Sprintf("%d", s.Errors), Inline: true})
	}

	title := "✅ Scan Complete"
	if s.Alerted > 0 {
		title = fmt.Sprintf("⚠️ Scan Complete — %d Alert(s) Sent", s.Alerted)
	}

	embed := Embed{
		Title:     title,
		Color:     embedColor,
		Fields:    fields,
		Footer:    &Footer{Text: "CamScan • Scan Summary"},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	payload := webhookPayload{
		Username: "CamScan",
		Embeds:   []Embed{embed},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal summary payload: %w", err)
	}

	for attempt := 0; attempt < 3; attempt++ {
		resp, err := n.httpClient.Post(n.webhookURL, "application/json", bytes.NewBuffer(body))
		if err != nil {
			return fmt.Errorf("failed to send summary webhook: %w", err)
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := resp.Header.Get("Retry-After")
			wait := 5 * time.Second
			if secs, parseErr := strconv.Atoi(retryAfter); parseErr == nil && secs > 0 {
				wait = time.Duration(secs) * time.Second
			}
			time.Sleep(wait)
			continue
		}

		return fmt.Errorf("discord summary webhook returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return fmt.Errorf("discord summary webhook rate limited after 3 retries")
}
